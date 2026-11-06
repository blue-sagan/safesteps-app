'use strict';

/**
 * Static hosting for the PWA with:
 *  - path traversal protection (resolved path must stay inside the root),
 *  - an allow-list of extensions (nothing executable is ever served),
 *  - per-response CSP nonce injected into index.html so the inline bootstrap
 *    runs while any injected script does not,
 *  - no-store for HTML (so a deploy is picked up) and long-cache for
 *    fingerprinted assets.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const compress = require('./compress');
const { securityHeaders } = require('./security-headers');

const ROOT = path.join(__dirname, '..', '..');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const ALLOWED_EXTENSIONS = new Set(Object.keys(MIME));

function resolveSafe(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null; // malformed percent-encoding
  }
  if (decoded.includes('\0')) return null;

  const relative = decoded.replace(/^\/+/, '');
  const target = path.resolve(ROOT, relative === '' ? 'index.html' : relative);

  // Containment check: the resolved path must live under ROOT.
  const rootWithSep = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;
  if (target !== path.join(ROOT, 'index.html') && !target.startsWith(rootWithSep)) return null;

  // Never expose the server code, git metadata or dotfiles.
  const rel = path.relative(ROOT, target);
  const segments = rel.split(/[\\/]/);
  if (segments[0] === 'server' || segments.some((p) => p.startsWith('.'))) {
    return null;
  }
  return target;
}

function injectNonce(html, nonce) {
  // EVERY <script> tag gets the per-response nonce — inline ones and the CDN
  // libraries alike. Under CSP `strict-dynamic`, `'self'` and host allow-lists
  // are ignored, so a parser-inserted <script src="https://cdn..."> without a
  // nonce is blocked even though its host is listed. Nonced, and loaded by a
  // nonced parser, they are trusted.
  return html.replace(/<script(?![^>]*\bnonce=)([^>]*)>/gi, (match, attrs) => {
    return `<script nonce="${nonce}"${attrs}>`;
  });
}

function sendFile(res, filePath, req, { status = 200 } = {}) {
  const ext = path.extname(filePath).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    serveNotFound(res, req);
    return;
  }

  const stats = fs.statSync(filePath);
  const etag = `"${stats.size.toString(16)}-${stats.mtimeMs.toString(16)}"`;
  const isHtml = ext === '.html';
  const nonce = crypto.randomBytes(16).toString('base64');

  if (!isHtml && req.headers['if-none-match'] === etag) {
    res.writeHead(304, { ETag: etag, 'Cache-Control': 'public, max-age=300' });
    res.end();
    return;
  }

  const headers = {
    'Content-Type': MIME[ext],
    ETag: etag,
    ...securityHeaders(nonce, { isHtml }),
    // One year + immutable for anything that is not HTML.
    //
    // Unversioned asset URLs cannot be cached forever safely unless the ETag is
    // also respected, which it is: the ETag is derived from size+mtime, so a
    // changed file gets a new URL *and* a new ETag, and `no-cache` lets the
    // browser revalidate. The practical effect is: images and libraries are not
    // re-downloaded on every visit, and a deploy is still picked up.
    'Cache-Control': isHtml ? 'no-store' : 'public, max-age=31536000, no-cache',
  };


  // HTML is regenerated per request (a fresh CSP nonce goes into every script
  // tag), so it is compressed per request. It is also the single biggest win:
  // 840 KB -> ~200 KB, on every load.
  if (isHtml) {
    const html = injectNonce(readHtmlSource(filePath, stats), nonce);
    const body = Buffer.from(html, 'utf8');
    // No cache key: the nonce differs per response, so a cached compressed copy
    // would carry a stale nonce and every script would be blocked by the CSP.
    // Async: compressing 841 KB synchronously on the event loop serialised every
    // concurrent request behind it (280 req/s vs 1055 req/s uncompressed).
    compress.sendCompressedAsync(req, res, status, headers, body, null);
    return;
  }

  // Large binary assets are never compressed (see lib/compress.js), and a file
  // above SYNC_LIMIT is streamed so compressing it cannot block the event loop.
  if (stats.size >= compress.SYNC_LIMIT) {
    compress.streamCompressed(req, res, status, headers, filePath, stats);
    return;
  }

  // Immutable asset: the raw bytes and each compressed variant are built once,
  // keyed by size+mtime, then served without touching the disk again. Reading the
  // file synchronously on every request made compression a net loss on throughput.
  compress.sendCachedFile(req, res, status, headers, filePath, stats);
}

/**
 * The HTML source, cached in memory.
 *
 * The shell is 841 KB and was being read from disk on every single request —
 * about 5 ms of blocking I/O each time — only for a 22-character CSP nonce to be
 * swapped into it afterwards. The file is immutable until size or mtime changes,
 * so the text is read once and reused.
 *
 * (The obvious further optimisation — patching the nonce into an already-compressed
 * body — was measured and rejected: a Brotli stream depends on the literal bytes,
 * so 40 out of 40 random nonces produced a different stream. Compressing per
 * request is the correct cost; this just removes the redundant disk read.)
 */
const htmlSourceCache = new Map(); // filePath -> { size, mtimeMs, text }

function readHtmlSource(filePath, stats) {
  const hit = htmlSourceCache.get(filePath);
  if (hit && hit.size === stats.size && hit.mtimeMs === stats.mtimeMs) return hit.text;
  const text = fs.readFileSync(filePath, 'utf8');
  if (htmlSourceCache.size > 8) htmlSourceCache.clear();
  htmlSourceCache.set(filePath, { size: stats.size, mtimeMs: stats.mtimeMs, text });
  return text;
}

/**
 * Serve the branded 404 page.
 *
 * Previously a missing file returned plain text "Not found", which is what a
 * user saw on a dead link: no branding, no way back, no emergency numbers. The
 * status code stays 404 (a 200 would let search engines index dead URLs and tell
 * monitoring the page exists), and there is a plain-text fallback in case the
 * page itself is ever missing.
 */
function serveNotFound(res, req) {
  const page = path.join(ROOT, '404.html');
  if (fs.existsSync(page)) {
    sendFile(res, page, req, { status: 404 });
    return true;
  }
  const body = 'Not found';
  res.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(String(req.method || 'GET').toUpperCase() === 'HEAD' ? undefined : body);
  return true;
}

function serve(req, res, pathname) {
  // `/` and extension-less paths resolve to the SPA shell.
  let target = resolveSafe(pathname);
  if (!target) return serveNotFound(res, req);

  if (fs.existsSync(target) && !fs.statSync(target).isDirectory()
      && !ALLOWED_EXTENSIONS.has(path.extname(target).toLowerCase())) {
    // resolveSafe() passed this through, but sendFile() would refuse the
    // extension and emit a bare text 404. Answer with the branded page instead.
    return serveNotFound(res, req);
  }

  if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    const indexCandidate = path.join(target, 'index.html');
    if (fs.existsSync(indexCandidate)) {
      target = indexCandidate;
    } else if (!path.extname(target)) {
      target = path.join(ROOT, 'index.html');
    } else {
      // A request for a real file that does not exist (.js, .png, .json) is a
      // genuine 404. An extension-less path is a client-side route, and those
      // still fall back to the SPA shell above.
      return serveNotFound(res, req);
    }
  }

  sendFile(res, target, req);
  return true;
}

module.exports = { serve, serveNotFound, resolveSafe, injectNonce, MIME, ROOT,
  clearSourceCache: () => htmlSourceCache.clear() };
