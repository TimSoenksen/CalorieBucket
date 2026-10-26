# Calorie Bucket

A live, draining bucket of your energy balance. Food pours in, exercise opens the tap, and your estimated weight ticks down second by second.

- `public/index.html` is the whole app: plain HTML, CSS and JavaScript.
- `src/worker.js` is a small Cloudflare Worker that saves your log per signed-in person, so your phone and computer share one log.
- `wrangler.jsonc` is the Cloudflare config. Storage is a Durable Object, which Cloudflare creates automatically on deploy.

The page always keeps a copy in the browser too, so it works offline and syncs when it can reach the server.

## Setting up sign-in (one time)

1. **Protect the site with Cloudflare Access.** In Cloudflare Zero Trust, go to Access → Applications → Add an application → Self-hosted. Add your Worker's hostname (for example `caloriebucket.<you>.workers.dev`, or your custom domain). Add a policy that allows only your email.
   - If you use a custom domain, turn off the `workers.dev` route in the Worker's settings so the app can't be reached around Access. If you keep `workers.dev`, enable Access on it from the Worker's Settings → Domains & Routes.
2. **Copy two values into `wrangler.jsonc`** under `vars`:
   - `ACCESS_TEAM_DOMAIN`: your team domain, like `yourteam.cloudflareaccess.com` (Zero Trust → Settings → Custom Pages, or the URL of your Access login page).
   - `ACCESS_AUD`: the **Application Audience (AUD) Tag** on the Access application's overview page.
3. Commit and push. Cloudflare redeploys, and the header shows "Synced to you@example.com" once it's working.

The Worker checks the Access token's signature, issuer, audience and expiry on every request, so it doesn't rely on Access alone.
