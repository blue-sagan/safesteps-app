# Performance

What was measured, what changed, and what was deliberately *not* changed.

Everything below was measured on this repository's own code, not estimated. Where
a recommendation from the brief was not followed, the reason is written down —
usually because verifiable correctness beat an unverifiable speed-up in a safety
app.

Reproduce any of it with:

```
node scripts/check-performance.js            # budget + regression gate (in CI)
node scripts/smoke-test.js http://127.0.0.1:8080   # load, latency, offline shell
```

## The headline number

| | Before | After |
|---|---|---|
| App shell on the wire (Brotli) | 841 KB uncompressed | **221 KB** |
| App shell, gzip | 841 KB | 236 KB |
| Responsive stylesheets | 1 font `@import` chain | 0 `@import`s, preconnected |

841 KB on a Kenyan mobile connection at ~1 Mbps is roughly 7 seconds of transfer
before the phone parses anything. 221 KB is about 2 seconds. This is the single
change that affects every user on every visit.

Measured with `scripts/check-performance.js`, which fails CI if it regresses.

## What was done

### Server-side compression (`lib/compress.js`)

Brotli and gzip, negotiated from `Accept-Encoding`, using only `node:zlib` — no
dependency added.

- Brotli quality 3: **221 KB at 8 ms** per compression. gzip level 4: 236 KB at
  12 ms. Brotli is used whenever the client offers it.
- Already-compressed types (PNG, JPEG, ICO) are never re-compressed. Re-encoding
  a PNG costs CPU and usually makes it bigger. There is a test for this.
- Assets under 1 KB, and responses that already carry `Content-Encoding`, are
  left alone.
- HTML is compressed **asynchronously**, on the libuv thread pool. This matters:
  the first version compressed synchronously, which blocks the single event loop
  for ~8 ms per navigation and dropped the server to 280 req/s with p95 climbing.
  Moving it off the event loop recovered most of the throughput (401 req/s in
  `smoke-test.js`, p95 148 ms, zero 5xx).

### Static assets are read once

The shell was being read off disk on every request, only for a 22-character CSP
nonce to be swapped into it. The source text and each compressed variant are now
cached in memory, keyed by size+mtime so a deploy still invalidates them. The
raw bytes are cached too, so a repeated asset request is a memory copy rather
than a disk read plus a compression.

### Browser caching

Assets were served with `max-age=604800`; they are now
`public, max-age=31536000, no-cache`, and `no-cache` means *revalidate*, not
*don't store*. Combined with the size+mtime `ETag`, a repeat visit sends a cheap
`304` instead of re-downloading, and a deploy is still picked up immediately.
`immutable` was deliberately **not** used: asset URLs are unversioned, so it
would pin stale files after a release.

### Fonts

The two Google Fonts families were pulled in with `@import` at the top of a
~40 KB `<style>` block. That serialises the whole chain: parse the CSS, discover
the import, connect, download, download again for the font files. They are now
`<link rel="stylesheet">` tags, discovered by the preload scanner immediately,
with `preconnect` to both `fonts.googleapis.com` and `fonts.gstatic.com` so the
DNS and TLS round trips happen in parallel with parsing.

Only the weights the app uses are requested. The `<noscript>` fallback keeps it
working with JavaScript off.

Self-hosting the fonts would be better still — it would remove two third-party
origins entirely — but that means adding several hundred KB of `.woff2` files to
the repository, which is a decision for whoever owns the hosting bill, not
something to do silently. It is listed under "not done" below.

### Images

- 21 byte-identical duplicate images deleted (2.66 MB that was never referenced).
- Remaining icons and screenshots re-encoded as PNG8 with Floyd–Steinberg
  dithering, gated at `MIN_PSNR 36 dB` so a visually lossy result is rejected.
  Result: 2.60 MB → 1.56 MB. `icon-512.png` went from 318 KB to 121 KB at
  38.5 dB and is visually indistinguishable.
- The below-the-fold poster now carries its real `width`/`height` (480×715) and
  `decoding="async"`, so the space is reserved before it loads and the page does
  not shift when it arrives.

### Search inputs

Both search boxes ran their filter on every keystroke. The SACCO lookup rebuilds
a dozen cards per character. They are now debounced at 200 ms.

## What was deliberately not done

These were on the list. They are not done for a reason, and the reason matters
more than the checkmark.

### Splitting the JavaScript by page

The app is a single classic script of ~625 KB (about 160 KB Brotli) that cannot
be split without restructuring how it initialises: every screen is in one
document and one lexical scope, and 400+ inline `onclick` handlers reference
globals by name. Converting it to modules and lazily importing screens per route
is a rewrite of the app's structure, not an optimisation. It is the right thing
to do eventually; it is not a safe thing to do in a polish pass on a road-safety
app that schoolchildren use.

### Self-hosting the fonts

Would remove two third-party origins and two DNS+TLS handshakes. Needs the
`.woff2` files committed (400–600 KB across the weights actually used) and a
licence check. Flagged, not done.

### Serving images as WebP or AVIF

The ImageMagick build available here has no WebP encoder, and no `cwebp`,
`pngquant` or `optipng`. Rather than ship untested conversions, the PNGs were
optimised with a measured quality gate. WebP would save roughly another 25% on
the screenshots and is worth doing wherever a WebP-capable toolchain exists.

### Deferring the third-party scripts

They were moved to `defer` and then **reverted**, deliberately. The app
initialises the hazard map (Leaflet), the QR code and the sign scanner during
start-up. With `defer`, the app's own script runs first, the libraries are still
in flight, and the guarded `typeof L === "undefined"` branches take the
"library missing" path — the map would simply never render. Silent breakage in
exchange for a few hundred milliseconds is the wrong trade. They stay
synchronous at the bottom of the document, so the cost is paid after the markup
is parsed but before initialisation needs them.

Fixing this properly means making those initialisers wait for a `load` event;
that is a real change with a real regression risk, and it should be done with a
device to test on.

### A virtual list for the community feed and hazard list

Both lists are bounded by what is in this device's own `localStorage` — a few
dozen items at most — not by a paginated API. Virtualising them would add
complexity and scroll bugs to save nothing measurable.

### Streaming AI responses token by token

There is no AI chat endpoint. The "Ask SafeSteps" screen answers from a local
rule-based knowledge base; there is no model call to stream.

## Server-side and data-layer items from the brief

| Recommendation | Status |
|---|---|
| Prevent duplicate API calls | `dedupeGet()` in `index.html` shares in-flight GETs |
| Debounce search inputs | Done, 200 ms on both search boxes |
| Timeouts on external calls | Client default lowered 20 s → 12 s (uploads keep 30 s); the server already times out its own calls |
| Set timeouts on external API calls | `AbortSignal.timeout` on every outbound `fetch` in `lib/` |
| Select only the columns you need | Already done — `lib/api.js` passes explicit `select=` lists and never `select=*` |
| Move slow tasks to a queue | Mail is already queued (`outbound_mail`); analytics is buffered and batch-flushed |
| Background job queue | Not added. Nothing in the current request path is slow enough to need one, and a queue without a worker to run it is theatre |
| Add a database index | Done in the same migrations, including the new `bug_reports` indexes |
| Fix N+1 queries | Not applicable — the server issues one PostgREST call per request; there is no in-process query loop over related rows |
| Connection pooling | Not ours to configure: PostgREST handles pooling in front of Postgres |
| Place servers near the database | Deployment decision; noted in `docs/ROLLBACK.md` |
| Trace slow requests with OpenTelemetry | Not added — it is a runtime dependency on a server that currently has **zero** runtime dependencies, which is a deliberate security property. `/healthz` already exposes uptime, analytics counters and flush failures; latency percentiles come from `smoke-test.js` |
| Browser caching | Done (see above) |
| Serve static files through a CDN | Deployment decision. The server already sets correct `ETag`/`Cache-Control`, so a CDN in front of it needs no code change |
| Brotli or Gzip | Done (see above) |
| SSR or SSG | Not applicable — this is an offline-first PWA whose whole point is running from a service worker cache with no server |
| Load balancing | Deployment decision; the app keeps no session state in process memory beyond rate-limit windows, which fall back to the database |
| Remove unused dependencies | Already zero runtime dependencies; verified by `scripts/security-audit.sh` |
| Track real user speeds | Not added. It would need a performance-monitoring vendor or a new first-party metric, and the privacy policy promises no third-party analytics. `check-performance.js` covers the regression side |
| Test on slow phones and poor networks | Cannot be done here: there is no browser engine and no throttled network in this environment. `smoke-test.js` is the closest available proxy. **A real mid-range Android phone on a throttled connection is still required before launch.** |

## The honest caveat

There is no browser engine in this environment. `check-performance.js` measures
bytes, request counts and blocking resources — things that can be measured
exactly from the source — and makes no claim about paint timings, LCP or
interaction latency. Those need a real device, and the brief's own advice ("test
on slow phones under poor network conditions") is exactly the step that cannot be
performed here.
