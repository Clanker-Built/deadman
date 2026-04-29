"use strict";
// Client-side bundle encryption. Uses WebCrypto (universal browser support):
//   - AES-256-GCM for payload
//   - RSA-OAEP-SHA256 to wrap the DEK against the server release public key
// Produces an opaque blob that server never decrypts outside the release
// pipeline.

(function () {
  function b64urlEncode(buf) {
    var bytes = new Uint8Array(buf);
    // Chunk to avoid String.fromCharCode.apply stack limits on large buffers.
    var bin = "";
    var chunk = 0x8000;
    for (var i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function sha256(buf) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  }

  // Pack multiple files into a simple TLV layout that the release worker
  // can re-split at unseal time:
  //   [u32 name_len | name | u64 content_len | content] ...
  function packFiles(files) {
    var enc = new TextEncoder();
    var parts = [];
    var total = 0;
    return Promise.all(Array.from(files).map(function (f) {
      return f.arrayBuffer().then(function (buf) {
        var name = enc.encode(f.name);
        var nameLen = new DataView(new ArrayBuffer(4));
        nameLen.setUint32(0, name.length, false);
        var contentLen = new DataView(new ArrayBuffer(8));
        // JS can't losslessly handle u64 > 2^53 but 256MiB ceiling <<.
        contentLen.setBigUint64(0, BigInt(buf.byteLength), false);
        parts.push(nameLen.buffer, name, contentLen.buffer, buf);
        total += 4 + name.length + 8 + buf.byteLength;
      });
    })).then(function () {
      var out = new Uint8Array(total);
      var off = 0;
      parts.forEach(function (p) {
        var v = p instanceof Uint8Array ? p : new Uint8Array(p);
        out.set(v, off);
        off += v.length;
      });
      return out.buffer;
    });
  }

  async function encryptAndUpload(form, status, progress) {
    var label = form.label.value.trim();
    var files = form.files.files;
    if (!files || files.length === 0) throw new Error("pick at least one file");

    status.textContent = "Packing files…";
    var packed = await packFiles(files);

    status.textContent = "Fetching release public key…";
    var pkResp = await fetch("/api/v1/release/pubkey", { credentials: "same-origin" });
    if (!pkResp.ok) throw new Error("release key fetch: " + await pkResp.text());
    var pk = await pkResp.json();
    var pubKey = await crypto.subtle.importKey(
      "jwk", pk.jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
    );

    status.textContent = "Generating encryption key…";
    var dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt"]
    );
    var dekRaw = await crypto.subtle.exportKey("raw", dek);

    // Manifest binds context to the AEAD tag via AAD.
    var manifest = JSON.stringify({
      label: label,
      file_count: files.length,
      total_bytes: packed.byteLength,
      packed_scheme: "tlv.v1",
    });
    var manifestBytes = new TextEncoder().encode(manifest);
    var manifestHash = await sha256(manifestBytes.buffer);

    status.textContent = "Encrypting " + Math.round(packed.byteLength / 1024) + " KiB…";
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: manifestHash },
      dek, packed
    ));
    var ciphertext = new Uint8Array(nonce.length + ct.length);
    ciphertext.set(nonce, 0);
    ciphertext.set(ct, nonce.length);

    status.textContent = "Wrapping encryption key…";
    var wrapped = new Uint8Array(await crypto.subtle.encrypt(
      { name: "RSA-OAEP", label: new TextEncoder().encode("deadman/release-wrap/v1") },
      pubKey, dekRaw
    ));

    status.textContent = "Uploading…";
    progress.hidden = false;
    progress.value = 50;
    var resp = await fetch("/api/v1/bundles/", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: label,
        ciphertext: b64urlEncode(ciphertext),
        manifest_hash: b64urlEncode(manifestHash),
        manifest: b64urlEncode(manifestBytes),
        wrapped_bundle_key: b64urlEncode(wrapped),
        wrap_scheme: "rsa-oaep-sha256.aes-gcm.v1",
      }),
    });
    progress.value = 100;
    if (!resp.ok) throw new Error("upload: " + resp.status + " " + await resp.text());
    var body = await resp.json();
    status.textContent = "Uploaded. Bundle id: " + body.id;
    setTimeout(function () { window.location.href = "/ui/dashboard"; }, 1500);
  }

  window.__deadmanBundleInit = function () {
    var form = document.getElementById("bundle-form");
    var status = document.getElementById("bundle-status");
    var progress = document.getElementById("bundle-progress");
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      try { await encryptAndUpload(form, status, progress); }
      catch (err) { status.textContent = "Failed: " + err.message; }
    });
  };
})();
