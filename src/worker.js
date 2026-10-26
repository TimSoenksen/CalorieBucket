// Calorie Bucket API.
// Static files in ./public are served directly. Requests to /api/* land here.
// Cloudflare Access sits in front of the whole site; this Worker verifies the
// Access token itself and keeps one private store per signed-in email.

import { DurableObject } from "cloudflare:workers";

/* ---------- per-user storage ---------- */
// "Delete all my data" records when it happened. Any device that later sends a log
// started before that moment gets told to clear itself instead of bringing the data back.
export class UserStore extends DurableObject {
  async load() {
    const s = await this.ctx.storage.get("state");
    return s && s.profile ? s : null;
  }
  async resetAt() {
    return (await this.ctx.storage.get("resetAt")) || 0;
  }
  async read() {
    return { state: await this.load(), resetAt: await this.resetAt() };
  }
  async save(incoming) {
    const resetAt = await this.resetAt();
    if (incoming?.profile && incoming.profile.start <= resetAt) return { state: await this.load(), resetAt };
    const merged = merge(await this.load(), incoming);
    if (merged) await this.ctx.storage.put("state", merged);
    return { state: merged, resetAt };
  }
  async wipe(at) {
    const now = Date.now();
    const resetAt = Number.isFinite(at) && at > 0 && at < now + DAY_MS ? at : now;
    await this.ctx.storage.delete("state");
    await this.ctx.storage.put("resetAt", resetAt);
    return { state: null, resetAt };
  }
}
const DAY_MS = 864e5;

// Combine what's stored with what a device sent, so two devices never erase each other.
// - "Start over" picks a new start time, and the newest start wins outright.
// - Otherwise entries are combined by id, and deleted ids stay deleted.
// - The most recently edited profile wins.
function merge(stored, incoming) {
  if (!incoming || incoming.example || !incoming.profile) return stored;
  if (!stored) return clean(incoming);
  if (stored.profile.start !== incoming.profile.start) {
    return clean(incoming.profile.start > stored.profile.start ? incoming : stored);
  }
  const deleted = [...new Set([...(stored.deleted || []), ...(incoming.deleted || [])])];
  const dead = new Set(deleted);
  const byId = new Map();
  for (const e of [...(stored.entries || []), ...(incoming.entries || [])]) {
    if (!dead.has(e.id)) byId.set(e.id, e);
  }
  const newer = (incoming.profileAt || 0) >= (stored.profileAt || 0) ? incoming : stored;
  return clean({
    profile: newer.profile,
    profileAt: newer.profileAt || 0,
    entries: [...byId.values()],
    deleted,
  });
}
function clean(s) {
  return {
    example: false,
    profile: s.profile,
    profileAt: s.profileAt || 0,
    entries: [...(s.entries || [])].sort((a, b) => a.ts - b.ts),
    deleted: (s.deleted || []).slice(-1000),
  };
}

/* ---------- Cloudflare Access token check ---------- */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

let certCache = { at: 0, team: "", keys: [] };
async function accessKeys(team) {
  if (certCache.team === team && Date.now() - certCache.at < 3600_000) return certCache.keys;
  const r = await fetch(`https://${team}/cdn-cgi/access/certs`);
  if (!r.ok) throw new HttpError(500, `Couldn't load Access keys from ${team}. Check ACCESS_TEAM_DOMAIN.`);
  const { keys } = await r.json();
  certCache = { at: Date.now(), team, keys };
  return keys;
}

const b64 = (s) => s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
const b64Bytes = (s) => Uint8Array.from(atob(b64(s)), (c) => c.charCodeAt(0));
const b64Json = (s) => JSON.parse(new TextDecoder().decode(b64Bytes(s)));

async function signedInEmail(request, env) {
  const team = (env.ACCESS_TEAM_DOMAIN || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  if (!team || !env.ACCESS_AUD) {
    throw new HttpError(500, "Server setup: fill in ACCESS_TEAM_DOMAIN and ACCESS_AUD in wrangler.jsonc.");
  }
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new HttpError(401, "Not signed in through Cloudflare Access.");

  const [h, p, sig] = token.split(".");
  let header, payload;
  try { header = b64Json(h); payload = b64Json(p); } catch { throw new HttpError(401, "Unreadable sign-in token."); }

  let keys = await accessKeys(team);
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) { certCache.at = 0; keys = await accessKeys(team); jwk = keys.find((k) => k.kid === header.kid); }
  if (!jwk) throw new HttpError(401, "Sign-in token was signed by an unknown key.");

  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64Bytes(sig), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) throw new HttpError(401, "Sign-in token signature didn't check out.");

  const now = Date.now() / 1000;
  if (payload.exp && payload.exp < now) throw new HttpError(401, "Sign-in expired. Reload to sign in again.");
  if (payload.iss !== `https://${team}`) throw new HttpError(401, "Sign-in token is from a different Access team.");
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(env.ACCESS_AUD)) throw new HttpError(403, "Sign-in token is for a different Access application.");
  if (!payload.email) throw new HttpError(403, "Sign-in token has no email.");
  return payload.email.toLowerCase();
}

/* ---------- routes ---------- */
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);

    try {
      if (url.pathname !== "/api/state") throw new HttpError(404, "No such endpoint.");
      const email = await signedInEmail(request, env);
      const store = env.STORE.get(env.STORE.idFromName(email));

      if (request.method === "GET") {
        return json({ email, ...(await store.read()) });
      }
      if (request.method === "PUT") {
        const body = await request.json().catch(() => null);
        if (!body || typeof body.state !== "object") throw new HttpError(400, "Expected { state }.");
        return json({ email, ...(await store.save(body.state)) });
      }
      if (request.method === "DELETE") {
        const body = await request.json().catch(() => ({}));
        return json({ email, ...(await store.wipe(body?.at)) });
      }
      throw new HttpError(405, "Use GET, PUT or DELETE.");
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      return json({ error: err.message || "Something went wrong." }, status);
    }
  },
};
