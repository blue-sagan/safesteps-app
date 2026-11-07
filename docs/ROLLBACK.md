# Rollback

Section C: "implement rollback procedures" and "test updates before deployment".

A rollback is not `git revert` on its own. SafeSteps has four things that can be
out of step during a bad release, and fixing only one of them is how a rollback
appears to do nothing:

| Layer | What goes wrong | Why a revert alone is not enough |
| --- | --- | --- |
| **Server** (Render) | the process is running bad code | it redeploys automatically, but the old process may still be draining |
| **Service worker** | users keep the cached old app shell | `CACHE_VERSION` gates cache eviction; a rollback that does not bump it is invisible to existing users |
| **Database** | a migration changed the schema | schema changes are not undone by deploying old code |
| **Config** | an env var changed | deploy history and env history are separate |

---

## 1. Before you deploy

Run these three. All must pass.

```bash
cd safesteps/server && node --test test/*.test.js    # 67 tests
cd ../.. && node scripts/check-mobile.js             # layout on 8 phone sizes
node scripts/check-release.js --since origin/main    # cache-bump + assets
```

Then `./scripts/security-audit.sh` and `./scripts/verify-deployment.sh <url>`.

`check-release.js` is the one that catches the mistake that actually bites: an
app-shell file changed but `sw.js`'s `CACHE_VERSION` was not bumped. In that
case every existing install keeps serving the previous HTML from cache, so a fix
looks broken **and a rollback looks broken too**. Verified: changing
`index.html` without touching `sw.js` fails the gate; bumping the version passes.

Tag every deploy, because a tag is what you roll back *to*:

```bash
git tag -a v1.4.0 -m "SafeSteps 1.4.0" && git push origin v1.4.0
```

## 2. Decide fast: roll back or fix forward

Roll back when **any** of these is true:

- sign-up or sign-in is broken for everyone;
- the app does not load (shell broken, service worker stuck on a bad cache);
- data written by the new version is being corrupted;
- a security regression: secrets exposed, session handling wrong.

Fix forward when the problem is cosmetic, affects one screen, or data is
untouched. A rushed second deploy at an incident is its own risk.

## 3. Roll back the server

**Render** (per `render.yaml`, `autoDeploy: true`):

1. Dashboard → the `safesteps` service → **Deploys**.
2. Find the last known-good deploy → **⋯ → Rollback to this deploy**.
3. Watch the health check. `/healthz` must answer with a JSON body; note
   `platform.reachable`.

**By commit**, if you need to build from source:

```bash
git revert --no-commit <bad-commit>..HEAD
git commit -m "rollback: revert to <good-tag>"
```

The revert must include a `CACHE_VERSION` bump. That is not cosmetic — without
it, every device keeps the broken shell and your rollback does nothing. Say so
in the commit message so the next person does not "tidy it away".

Check afterwards:

```bash
curl -s https://<host>/healthz
./scripts/verify-deployment.sh https://<host>
```

## 4. Roll back the service worker (the part people forget)

Symptom: the server is correct, but users still see the old app — often on
mobile only, and clearing "site data" fixes it.

1. Confirm the mismatch: the deployed `index.html` on the server differs from
   what the browser shows, and `sw.js`'s `CACHE_VERSION` is unchanged across
   the bad and good deploys.
2. Bump `CACHE_VERSION` **in the good release** and deploy that. On the next
   visit, `activate` deletes every cache that is not the current version and
   claims open clients, so the new shell replaces the old one.
3. For a user stuck right now: reload twice (the first load installs the new
   worker, the second is served by it), or Settings → clear site data.
4. Emergency lever if a bad worker cannot be displaced: ship a `sw.js` that
   only unregisters itself.

   ```js
   self.addEventListener('install', () => self.skipWaiting());
   self.addEventListener('activate', (e) =>
     e.waitUntil(self.registration.unregister().then(() => self.clients.matchAll())
       .then((cs) => cs.forEach((c) => c.navigate(c.url))))
   );
   ```

   Deploy that as `sw.js`, confirm clients recover, then restore the real worker
   with a higher `CACHE_VERSION`. This is a last resort — it removes offline
   support until the real worker returns.

## 5. Roll back the database

Server code can be reverted in a minute; a dropped column is not. Before
rolling back a release that included a migration:

1. **Take a backup first**, even mid-incident:
   `./scripts/db-backup.sh --out backups/incident-<date>`.
   See `docs/BACKUP-AND-RECOVERY.md`.
2. **Check whether the old code still runs against the new schema.** Additive
   changes (new nullable column, new table) are usually safe. Destructive ones
   (dropped or renamed column, changed type, tightened constraint) are not —
   old code will error on every request that touches that table.
3. **Prefer forward repair.** Re-adding a dropped column with a default is
   usually cheaper and safer than restoring the entire database and losing
   everything written since the backup.
4. **Restore** only when data is genuinely wrong:
   verify the bundle (`./scripts/db-restore-test.sh`), rehearse against a
   scratch project, then restore. Full runbook in `BACKUP-AND-RECOVERY.md` §6.

Migrations already applied are recorded by the platform; reverting the repo does
not un-apply them.

## 6. Roll back configuration

Deploy rollbacks do **not** revert environment variables. If the incident
started after an env change, fix the env directly: Render → Environment →
History, then redeploy. The server's `/healthz` lists which capabilities are
configured (booleans only) — after any env change, read it back rather than
assuming.

## 7. After any rollback

- `./scripts/verify-deployment.sh https://<host>` passes.
- Sign-up, sign-in and password reset each work once, by hand.
- The offline app loads with the network off (the service worker is healthy).
- Note in the incident log: what shipped, what was reverted, whether
  `CACHE_VERSION` was bumped, whether a migration needs repairing.

## 8. What is verified and what is not

Verified in this repository: the cache-bump gate fails when it should and
passes when it should; every pre-cached asset exists; the test suite, layout
audit and deployment check all run and pass.

**Not verified here:** an actual rollback on Render, because it needs the
dashboard. Treat steps 3–6 as a rehearsed *procedure*, not a tested one — walk
through it once on a staging service before launch. It takes ten minutes and it
is the ten minutes you will not have during an incident.
