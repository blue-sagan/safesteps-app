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
  if (rel.startsWith('server' + path.sep) || rel === 'server' || rel.split(path.sep).some((p) => p.startsWith('.'))) {
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
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
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
    'Cache-Control': isHtml ? 'no-store' : 'public, max-age=604800',
  };

  const isHead = req && req.method === 'HEAD';

  if (isHtml) {
    const html = injectNonce(fs.readFileSync(filePath, 'utf8'), nonce);
    const body = Buffer.from(html, 'utf8');
    headers['Content-Length'] = body.length;
    res.writeHead(status, headers);
    res.end(isHead ? undefined : body);
    return;
  }

  headers['Content-Length'] = stats.size;
  res.writeHead(status, headers);
  if (isHead) {
    res.end();
    return;
  }
  fs.createReadStream(filePath).pipe(res);
}

function serve(req, res, pathname) {
  // `/` and extension-less paths resolve to the SPA shell.
  let target = resolveSafe(pathname);
  if (!target) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return true;
  }

  if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) {
    const indexCandidate = path.join(target, 'index.html');
    if (fs.existsSync(indexCandidate)) {
      target = indexCandidate;
    } else if (!path.extname(target)) {
      target = path.join(ROOT, 'index.html');
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return true;
    }
  }

  sendFile(res, target, req);
  return true;
}

module.exports = { serve, resolveSafe, injectNonce, MIME, ROOT };
