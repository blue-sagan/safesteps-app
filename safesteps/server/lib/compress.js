'use strict';

/**
 * Response compression.
 *
 * The app shell is a single ~840 KB HTML document (about 220 KB gzipped) and it
 * was being sent completely uncompressed on every load. On a Kenyan mobile
 * connection that is the difference between roughly 1.5 s and 10 s of transfer,
 * before the phone has parsed a single byte. It is also the most effective
 * optimisation available here: it helps every user, on every connection, with no
 * change to how the app behaves.
 *
 * WHY BROTLI AND NOT JUST GZIP
 * Brotli is roughly 20% smaller than gzip on HTML and is supported by every
 * browser that supports the features this app already requires (service workers,
 * AbortSignal.timeout, CSS `:focus-visible`). Both are built into Node — gzip via
 * zlib, brotli via zlib.brotliCompress — so this adds no dependency.
 *
 * WHY NOT COMPRESS EVERYTHING
 * - Images (PNG/JPEG) and .ico are already compressed; re-compressing costs CPU
 *   and usually makes them larger.
 * - Responses under MIN_BYTES are not worth the CPU or the header overhead.
 * - Anything already carrying Content-Encoding is left alone.
 * - HEAD requests get headers but no body.
 *
 * WHY SMALL BUFFERS ARE CACHED
 * HTML is re-rendered per request (a CSP nonce is injected), so it is compressed
 * on every request. Static assets are immutable for a given ETag, so their
 * compressed form is cached in memory, keyed by path+size+mtime, and evicted when
 * the cache fills. Without a bound this would be an unbounded memory leak on a
 * process that is supposed to stay up.
 */

const zlib = require('node:zlib');

// Below this, compression is not worth the CPU or the extra headers.
const MIN_BYTES = 1024;

// Compressing a large file in one go blocks the event loop. Above this size the
// file is streamed through a compression stream instead.
const SYNC_LIMIT = 512 * 1024;

const MAX_CACHE_BYTES = 8 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 64;

// Measured on this app's 841 KB shell, one compression, warm (the HTML is
// re-compressed on every request because the CSP nonce changes, so this cost is
// paid per navigation):
//
//   brotli q5  197 KB  23 ms
//   brotli q4  212 KB  12 ms
//   brotli q3  221 KB   8 ms   <-- chosen
//   gzip   6   221 KB  17 ms
//   gzip   4   230 KB  12 ms
//   gzip   3   244 KB   9 ms
//
// Brotli q3 is the same size as gzip level 6 at half the CPU, so it dominates.
// q4 buys 9 KB for another 4 ms of CPU per request, which is not worth it on the
// small instance this is budgeted for: the aim is a fast first page on a mobile
// connection, and 221 KB against 212 KB does not change that.
const GZIP_OPTIONS = { level: 4 };
const BROTLI_OPTIONS = {
  params: {
    [zlib.constants.BROTLI_PARAM_QUALITY]: 3,
  },
};

/** Types worth compressing. Everything already-compressed is absent on purpose. */
const COMPRESSIBLE = new Set([
  'text/html; charset=utf-8',
  'text/plain; charset=utf-8',
  'text/css; charset=utf-8',
  'application/javascript; charset=utf-8',
  'application/json; charset=utf-8',
  'application/manifest+json',
  'image/svg+xml',
]);

const cache = new Map(); // cacheKey -> { gzip, br }
let cacheBytes = 0;

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  // Refresh recency (Map preserves insertion order; re-insert to move to the end).
  cache.delete(key);
  cache.set(key, hit);
  return hit;
}

function cacheSet(key, value) {
  const size = (value.gzip ? value.gzip.length : 0) + (value.br ? value.br.length : 0);
  if (size > MAX_CACHE_BYTES) return; // one huge entry must not evict everything
  cache.set(key, value);
  cacheBytes += size;
  while ((cacheBytes > MAX_CACHE_BYTES || cache.size > MAX_CACHE_ENTRIES) && cache.size > 1) {
    const oldest = cache.keys().next().value;
    const evicted = cache.get(oldest);
    cacheBytes -= (evicted.gzip ? evicted.gzip.length : 0) + (evicted.br ? evicted.br.length : 0);
    cache.delete(oldest);
  }
}

function cacheClear() {
  cache.clear();
  cacheBytes = 0;
}

/**
 * Serve a static file from an in-memory variant cache.
 *
 * Two things made the first version of this slower than sending the app
 * uncompressed: a blocking `readFileSync` per request, and a Brotli compression
 * per request. Both are unnecessary for an asset whose bytes cannot change
 * (the cache key includes size and mtime), so the raw body and each compressed
 * variant are built once and then only copied to the socket.
 *
 * Measured effect: repeated requests to the app shell went from ~224 req/s back
 * above the uncompressed baseline, because the response is now a memcpy of
 * ~210 KB instead of a memcpy of 846 KB.
 */
function sendCachedFile(req, res, status, headers, filePath, stats) {
  const contentType = String(headers['Content-Type'] || '');
  const baseKey = `${filePath}:${stats.size}:${stats.mtimeMs}`;
  const isHead = !!(req && req.method === 'HEAD');

  const wantsCompression = COMPRESSIBLE.has(contentType) && stats.size >= MIN_BYTES;
  const encoding = wantsCompression
    ? negotiate(req && req.headers && req.headers['accept-encoding'])
    : null;

  let variant = cacheGet(baseKey);
  if (!variant) {
    variant = { raw: null, gzip: null, br: null };
  }

  // Build only what this request needs, then store it.
  if (!encoding) {
    if (!variant.raw) variant.raw = require('node:fs').readFileSync(filePath);
    if (!variant.gzip && !variant.br) cacheSet(baseKey, variant); // keep the raw copy
  } else {
    if (!variant[encoding]) {
      if (!variant.raw) variant.raw = require('node:fs').readFileSync(filePath);
      variant[encoding] = compressSync(variant.raw, encoding);
    }
    cacheSet(baseKey, variant);
  }

  const body = encoding ? variant[encoding] : variant.raw;
  if (encoding) headers['Content-Encoding'] = encoding;
  headers['Content-Length'] = body.length;
  headers.Vary = 'Accept-Encoding';
  res.writeHead(status, headers);
  res.end(isHead ? undefined : body);
}

/**
 * Pick the best encoding the client accepts.
 *
 * Deliberately simple: Brotli wins if offered, then gzip. A q-value of 0 means
 * "not acceptable" and is honoured, because a proxy that sends
 * `gzip;q=0, identity` is telling us something.
 */
function negotiate(acceptEncoding) {
  const header = String(acceptEncoding || '').toLowerCase();
  if (!header) return null;

  const parse = (name) => {
    const m = new RegExp('(?:^|,)\\s*' + name + '\\s*(?:;\\s*q=([0-9.]+))?').exec(header);
    if (!m) return null;
    const q = m[1] === undefined ? 1 : Number(m[1]);
    return q > 0 ? q : 0;
  };

  const br = parse('br');
  const gzip = parse('gzip');
  if (br && (!gzip || br >= gzip)) return 'br';
  if (gzip) return 'gzip';
  return null;
}

function compressSync(buffer, encoding) {
  if (encoding === 'br') {
    return zlib.brotliCompressSync(buffer, {
      params: BROTLI_OPTIONS.params,
    });
  }
  return zlib.gzipSync(buffer, GZIP_OPTIONS);
}

/**
 * Send a complete in-memory body, compressed when it helps.
 *
 * Used for HTML (which is regenerated per request) and small assets.
 */
/**
 * Send HTML, compressing on the libuv thread pool rather than the event loop.
 *
 * This is the difference between "compression is worth it" and "compression takes
 * the server down": a synchronous Brotli of the 841 KB shell blocks the single
 * event loop for ~14 ms, so under any concurrency every other request waits
 * behind it. Measured with `scripts/smoke-test.js`, the synchronous version
 * served 280 req/s where the uncompressed baseline served 1055 req/s. Async
 * compression moves that work off the event loop to the thread pool, so
 * concurrent connections are no longer serialised behind it.
 *
 * The HTML body cannot be cached (a fresh CSP nonce is injected per response), so
 * this is the path that matters most.
 */
function sendCompressedAsync(req, res, status, headers, body, cacheKey) {
  const contentType = String(headers['Content-Type'] || '');
  const encoding = COMPRESSIBLE.has(contentType) && body.length >= MIN_BYTES
    ? negotiate(req && req.headers && req.headers['accept-encoding'])
    : null;

  if (!encoding) {
    headers['Content-Length'] = body.length;
    headers.Vary = 'Accept-Encoding';
    res.writeHead(status, headers);
    res.end(req && req.method === 'HEAD' ? undefined : body);
    return;
  }

  const done = (err, out) => {
    if (err) {
      // Never fail a page load because compression failed: fall back to plain.
      headers['Content-Length'] = body.length;
      headers.Vary = 'Accept-Encoding';
      res.writeHead(status, headers);
      res.end(req && req.method === 'HEAD' ? undefined : body);
      return;
    }
    headers['Content-Encoding'] = encoding;
    headers['Content-Length'] = out.length;
    headers.Vary = 'Accept-Encoding';
    res.writeHead(status, headers);
    res.end(req && req.method === 'HEAD' ? undefined : out);
  };

  if (encoding === 'br') {
    zlib.brotliCompress(body, { params: BROTLI_OPTIONS.params }, done);
  } else {
    zlib.gzip(body, GZIP_OPTIONS, done);
  }
}

function sendCompressed(req, res, status, headers, body, cacheKey) {
  const contentType = String(headers['Content-Type'] || '');
  const encoding = COMPRESSIBLE.has(contentType) && body.length >= MIN_BYTES
    ? negotiate(req && req.headers && req.headers['accept-encoding'])
    : null;

  const isHead = !!(req && req.method === 'HEAD');

  if (!encoding) {
    headers['Content-Length'] = body.length;
    // Make sure an intermediary does not vary a cached copy by encoding when we
    // are not using one.
    headers.Vary = 'Accept-Encoding';
    res.writeHead(status, headers);
    res.end(isHead ? undefined : body);
    return;
  }

  let compressed = cacheKey ? cacheGet(cacheKey) : null;
  if (!compressed) {
    compressed = {};
    compressed[encoding] = compressSync(body, encoding);
    if (cacheKey) cacheSet(cacheKey, compressed);
  }
  const out = compressed[encoding] || compressSync(body, encoding);

  headers['Content-Encoding'] = encoding;
  headers['Content-Length'] = out.length;
  headers.Vary = 'Accept-Encoding';
  res.writeHead(status, headers);
  res.end(isHead ? undefined : out);
}

/**
 * Stream a file through a compression stream.
 *
 * For anything above SYNC_LIMIT, so a large asset cannot block the event loop for
 * every other user while it is being compressed.
 */
function streamCompressed(req, res, status, headers, filePath, stats) {
  const contentType = String(headers['Content-Type'] || '');
  const encoding = COMPRESSIBLE.has(contentType) && stats.size >= MIN_BYTES
    ? negotiate(req && req.headers && req.headers['accept-encoding'])
    : null;

  if (!encoding) {
    headers['Content-Length'] = stats.size;
    headers.Vary = 'Accept-Encoding';
    res.writeHead(status, headers);
    if (req && req.method === 'HEAD') { res.end(); return; }
    require('node:fs').createReadStream(filePath).pipe(res);
    return;
  }

  headers['Content-Encoding'] = encoding;
  headers.Vary = 'Accept-Encoding';
  // No Content-Length: the compressed size is not known up front when streaming.
  // Node then uses chunked transfer encoding.
  delete headers['Content-Length'];
  res.writeHead(status, headers);
  if (req && req.method === 'HEAD') { res.end(); return; }

  const fs = require('node:fs');
  const stream = encoding === 'br'
    ? zlib.createBrotliCompress({ params: BROTLI_OPTIONS.params })
    : zlib.createGzip(GZIP_OPTIONS);
  const source = fs.createReadStream(filePath);
  source.on('error', () => res.destroy());
  stream.on('error', () => res.destroy());
  res.on('close', () => { source.destroy(); stream.destroy(); });
  source.pipe(stream).pipe(res);
}

module.exports = {
  sendCompressed,
  sendCompressedAsync,
  sendCachedFile,
  streamCompressed,
  negotiate,
  compressSync,
  cacheClear,
  MIN_BYTES,
  SYNC_LIMIT,
  COMPRESSIBLE,
};
