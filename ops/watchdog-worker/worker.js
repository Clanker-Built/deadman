// Deadman external watchdog — Cloudflare Worker.
//
// Design: zero trust in the thing we're watching. We fetch /watchdog, verify
// the Ed25519 signature with a pinned service public key (set in wrangler
// vars; no auto-rotation), and compare last-tick staleness to a threshold.
// If anything fails, we POST to ALERT_URL and log to console. A Cloudflare
// free-plan scheduled handler runs every minute.
//
// Ed25519 verification uses WebCrypto's raw "Ed25519" alg, supported on
// Cloudflare Workers runtime natively.

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(probe(env));
  },
  // Optional HTTP entry point — useful for manually kicking the probe.
  async fetch(req, env) {
    const result = await probe(env);
    return new Response(JSON.stringify(result, null, 2), {
      headers: { "content-type": "application/json" },
    });
  },
};

async function probe(env) {
  const url = env.WATCHDOG_URL;
  if (!url) return fail(env, "WATCHDOG_URL not set");

  let resp;
  try {
    resp = await fetch(url, { cf: { cacheTtl: 0, cacheEverything: false } });
  } catch (e) {
    return fail(env, `fetch error: ${e.message}`);
  }
  if (!resp.ok) return fail(env, `watchdog http ${resp.status}`);
  let body;
  try {
    body = await resp.json();
  } catch (e) {
    return fail(env, `watchdog non-json body`);
  }

  // Verify the service public key is pinned and matches what the endpoint
  // reports. If it doesn't match, that's a serious alert — either a key
  // rotation you didn't do, or an MitM.
  const pinned = env.SERVICE_PUBKEY_B64URL;
  if (!pinned) return fail(env, "SERVICE_PUBKEY_B64URL not set");
  if (body.service_pubkey !== pinned) {
    return fail(env, `service_pubkey mismatch. reported=${body.service_pubkey} pinned=${pinned}`);
  }

  // Verify signature.
  const pubBytes = b64urlToBytes(pinned);
  const sig = b64urlToBytes(body.signature);
  const payload = new TextEncoder().encode(body.payload);
  const key = await crypto.subtle.importKey(
    "raw", pubBytes, { name: "Ed25519" }, false, ["verify"]
  );
  const ok = await crypto.subtle.verify("Ed25519", key, sig, payload);
  if (!ok) return fail(env, "watchdog signature invalid");

  // Check staleness.
  const lastMs = Number(body.last_scheduler_ms || 0);
  const nowMs = Date.now();
  const ageSec = (nowMs - lastMs) / 1000;
  const threshold = Number(env.STALE_THRESHOLD_SECONDS || "300");
  if (lastMs === 0) return fail(env, "last_scheduler_ms = 0 (never ticked)");
  if (ageSec > threshold) {
    return fail(env, `scheduler stale: last tick ${ageSec.toFixed(0)}s ago (threshold ${threshold}s)`);
  }

  return { ok: true, age_seconds: ageSec };
}

async function fail(env, msg) {
  console.log("deadman-watchdog FAIL:", msg);
  if (env.ALERT_URL) {
    try {
      await fetch(env.ALERT_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-watchdog-secret": env.ALERT_SHARED_SECRET || "",
        },
        body: JSON.stringify({
          service: "deadman-watchdog",
          severity: "critical",
          message: msg,
          at: new Date().toISOString(),
          watchdog_url: env.WATCHDOG_URL,
        }),
      });
    } catch (e) {
      console.log("alert dispatch failed:", e.message);
    }
  }
  return { ok: false, error: msg };
}

function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
