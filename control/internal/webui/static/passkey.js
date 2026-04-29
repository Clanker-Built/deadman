"use strict";
// Vanilla WebAuthn client. Intentionally tiny so it stays auditable.
// No external calls, no transpiler. Works in current Firefox, Chrome, Safari.

(function () {
  // Base64URL decode -> Uint8Array.
  function b64urlDecode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64urlEncode(buf) {
    var s = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // go-webauthn emits challenge/user.id etc. as base64url strings in JSON.
  // Convert them back to ArrayBuffer fields the WebAuthn API expects.
  function materializeCreate(opts) {
    opts.publicKey.challenge = b64urlDecode(opts.publicKey.challenge);
    opts.publicKey.user.id = b64urlDecode(opts.publicKey.user.id);
    if (opts.publicKey.excludeCredentials) {
      opts.publicKey.excludeCredentials = opts.publicKey.excludeCredentials.map(function (c) {
        c.id = b64urlDecode(c.id); return c;
      });
    }
    return opts;
  }
  function materializeGet(opts) {
    opts.publicKey.challenge = b64urlDecode(opts.publicKey.challenge);
    if (opts.publicKey.allowCredentials) {
      opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map(function (c) {
        c.id = b64urlDecode(c.id); return c;
      });
    }
    return opts;
  }

  function credentialToJSON(cred, kind) {
    var r = cred.response;
    var body = {
      id: cred.id,
      rawId: b64urlEncode(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: b64urlEncode(r.clientDataJSON),
      },
    };
    if (kind === "register") {
      body.response.attestationObject = b64urlEncode(r.attestationObject);
    } else {
      body.response.authenticatorData = b64urlEncode(r.authenticatorData);
      body.response.signature = b64urlEncode(r.signature);
      if (r.userHandle) body.response.userHandle = b64urlEncode(r.userHandle);
    }
    return body;
  }

  async function registerFlow(form, status) {
    status.textContent = "Requesting registration challenge…";
    var email = form.email.value.trim();
    var displayName = form.display_name.value.trim();
    var beginResp = await fetch("/api/v1/auth/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email, display_name: displayName }),
    });
    if (!beginResp.ok) throw new Error("begin: " + (await beginResp.text()));
    var begin = await beginResp.json();

    status.textContent = "Touch your security key / passkey device to continue.";
    var opts = materializeCreate(begin.options);
    var cred = await navigator.credentials.create(opts);

    status.textContent = "Verifying credential…";
    var finishURL = "/api/v1/auth/register/finish?email=" + encodeURIComponent(email) +
                    "&session_id=" + encodeURIComponent(begin.session_id);
    var finishResp = await fetch(finishURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentialToJSON(cred, "register")),
    });
    if (!finishResp.ok) throw new Error("finish: " + (await finishResp.text()));
    status.textContent = "Account created. Logging you in…";
    // Chain into a login so the user lands on the dashboard with a cookie.
    await loginFlow(form, status);
  }

  async function loginFlow(form, status) {
    status.textContent = "Requesting login challenge…";
    var email = form.email.value.trim();
    var beginResp = await fetch("/api/v1/auth/login/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email }),
    });
    if (!beginResp.ok) throw new Error("begin: " + (await beginResp.text()));
    var begin = await beginResp.json();
    status.textContent = "Touch your passkey device…";
    var opts = materializeGet(begin.options);
    var assertion = await navigator.credentials.get(opts);
    status.textContent = "Verifying…";
    var finishURL = "/api/v1/auth/login/finish?email=" + encodeURIComponent(email) +
                    "&session_id=" + encodeURIComponent(begin.session_id);
    var resp = await fetch(finishURL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credentialToJSON(assertion, "login")),
      credentials: "same-origin",
    });
    if (!resp.ok) throw new Error("finish: " + (await resp.text()));
    status.textContent = "Logged in.";
    window.location.href = "/ui/dashboard";
  }

  window.__deadmanInit = function (cfg) {
    if (!window.PublicKeyCredential) {
      var s = document.getElementById(cfg.mode === "register" ? "register-status" : "login-status");
      if (s) s.textContent = "This browser does not support passkeys (WebAuthn). Try Firefox, Chrome, or Safari.";
      return;
    }
    var form = document.getElementById(cfg.mode + "-form");
    var status = document.getElementById(cfg.mode + "-status");
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      try {
        if (cfg.mode === "register") await registerFlow(form, status);
        else await loginFlow(form, status);
      } catch (err) {
        status.textContent = "Failed: " + err.message;
      }
    });
  };
})();
