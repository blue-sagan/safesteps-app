'use strict';

/**
 * Upload validation.
 *
 * The client-declared Content-Type and filename extension are both forgeable,
 * so neither is trusted. Every upload is:
 *   1. size-capped before and while buffering,
 *   2. sniffed from the leading bytes ("magic numbers"),
 *   3. checked against an allow-list of image/audio/video types,
 *   4. re-named to a server-generated UUID + canonical extension, stored under
 *      `<userId>/` inside the private `integrity-evidence` bucket,
 *   5. hashed (SHA-256) and the hash stored alongside the row so the evidence
 *      file's integrity can be verified later.
 *
 * Executables, HTML, SVG (scriptable) and archives are rejected outright.
 */

const crypto = require('node:crypto');
const config = require('./config');

const SIGNATURES = [
  { mime: 'image/jpeg', ext: 'jpg', test: (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  {
    mime: 'image/png',
    ext: 'png',
    test: (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  },
  {
    mime: 'image/webp',
    ext: 'webp',
    test: (b) => b.subarray(0, 4).toString('ascii') === 'RIFF' && b.subarray(8, 12).toString('ascii') === 'WEBP',
  },
  {
    mime: 'video/mp4',
    ext: 'mp4',
    test: (b) => b.subarray(4, 8).toString('ascii') === 'ftyp',
  },
  {
    mime: 'video/webm',
    ext: 'webm',
    test: (b) => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3,
  },
  {
    mime: 'audio/webm',
    ext: 'webm',
    test: (b) => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3,
  },
  {
    mime: 'audio/mpeg',
    ext: 'mp3',
    test: (b) =>
      b.subarray(0, 3).toString('ascii') === 'ID3' || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0),
  },
];

// Never allowed, even if the bytes would otherwise look acceptable.
const DENY_EXTENSIONS = new Set([
  'html', 'htm', 'xhtml', 'svg', 'js', 'mjs', 'cjs', 'php', 'phtml', 'asp', 'aspx', 'jsp',
  'exe', 'dll', 'so', 'dylib', 'bat', 'cmd', 'com', 'sh', 'ps1', 'jar', 'apk', 'msi',
  'zip', 'rar', '7z', 'gz', 'tar', 'pdf', 'doc', 'docx',
]);

function sniff(buffer) {
  if (!buffer || buffer.length < 12) return null;
  for (const signature of SIGNATURES) {
    if (signature.test(buffer)) return signature;
  }
  return null;
}

function extensionOf(filename) {
  const match = String(filename || '').toLowerCase().match(/\.([a-z0-9]{1,8})$/);
  return match ? match[1] : '';
}

class UploadError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UploadError';
    this.status = 400;
    this.code = 'invalid_upload';
  }
}

/**
 * @param {Buffer} buffer       raw bytes
 * @param {string} filename     original name (used only for the deny-list check)
 * @param {string} [declaredMime] client-supplied Content-Type (cross-checked)
 * @returns {{ mime: string, ext: string, bytes: number, sha256: string }}
 */
function inspect(buffer, filename = '', declaredMime = '') {
  const max = config.security.uploads.maxBytes;
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new UploadError('No file data received.');
  if (buffer.length > max) {
    throw new UploadError(`Files must be smaller than ${Math.round(max / (1024 * 1024))} MB.`);
  }

  const ext = extensionOf(filename);
  if (DENY_EXTENSIONS.has(ext)) throw new UploadError('That file type is not accepted.');

  // Reject anything that starts with a markup/script marker regardless of type.
  const head = buffer.subarray(0, 512).toString('utf8').trimStart().toLowerCase();
  if (head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<?php') || head.startsWith('<svg')) {
    throw new UploadError('That file type is not accepted.');
  }

  const signature = sniff(buffer);
  if (!signature) throw new UploadError('Unsupported file format.');
  if (!config.security.uploads.allowed.has(signature.mime)) {
    throw new UploadError('Unsupported file format.');
  }

  // The declared type, when present, must agree with the sniffed type. A JPEG
  // labelled image/png is a mislabel, not a valid upload.
  const declared = String(declaredMime || '').split(';')[0].trim().toLowerCase();
  if (declared && declared !== 'application/octet-stream' && declared !== signature.mime) {
    throw new UploadError('File contents do not match the declared type.');
  }

  return {
    mime: signature.mime,
    ext: signature.ext,
    bytes: buffer.length,
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
  };
}

/** Deterministic, non-guessable object key scoped to the owner. */
function objectKey(userId, ext) {
  if (!/^[0-9a-f-]{36}$/i.test(String(userId))) throw new UploadError('Invalid owner.');
  return `${userId}/${crypto.randomUUID()}.${ext}`;
}

module.exports = { inspect, objectKey, sniff, UploadError, DENY_EXTENSIONS };
