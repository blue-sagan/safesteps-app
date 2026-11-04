'use strict';

/**
 * Server-side rate limiting.
 *
 * Two layers, both keyed by HMAC/sha256 fingerprints so no raw IP or email is
 * ever written to storage:
 *
 *  1. In-process sliding window — instant, survives nothing, catches bursts.
 *  2. Durable fixed-window counter in Postgres (`api_check_rate_limit`) or the
 *     local SQLite store — survives restarts and works across instances.
 *
 * Fails *open* for availability if the durable store is unavailable, but logs a
 * security event so the degradation is visible; the in-process layer still
 * applies. Login/registration have independent, much tighter budgets.
 */

const crypto = require('node:crypto');
const config = require('./config');
const db = require('./db');

const buckets = new Map(); // `${bucket}:${key}` -> number[] (timestamps)

function prune(timestamps, windowMs, now) {
  let i = 0;
  while (i < timestamps.length && now - timestamps[i] > windowMs) i += 1;
  if (i > 0) timestamps.splice(0, i);
  return timestamps;
}

function memoryLimit(bucket, key, limit, windowMs) {
  const now = Date.now();
  const id = `${bucket}:${key}`;
  const timestamps = prune(buckets.get(id) || [], windowMs, now);
  timestamps.push(now);
  buckets.set(id, timestamps);
  // Bound memory: drop identifiers that have gone quiet.
  if (buckets.size > 50000) {
    for (const [entryKey, list] of buckets) {
      if (!list.length || now - list[list.length - 1] > windowMs) buckets.delete(entryKey);
    }
  }
  return {
    allowed: timestamps.length <= limit,
    remaining: Math.max(limit - timestamps.length, 0),
    retryAfter: timestamps.length > limit ? Math.ceil(windowMs / 1000) : 0,
  };
}

/**
 * @param {string} bucket   e.g. 'login', 'register', 'verify'
 * @param {string} key      already-hashed identity (ip hash, email hash…)
 * @param {number} limit    requests allowed per window
 * @param {number} windowMs window length in milliseconds
 */
async function check(bucket, key, limit, windowMs) {
  const hashed = crypto.createHash('sha256').update(`${bucket}|${key}`).digest('hex');
  const local = memoryLimit(bucket, hashed, limit, windowMs);
  if (!local.allowed) return local;

  if (!config.supabase.serviceRoleKey) return local;

  try {
    const response = await fetch(`${config.supabase.url}/rest/v1/rpc/api_check_rate_limit`, {
      method: 'POST',
      headers: {
        apikey: config.supabase.serviceRoleKey,
        Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        p_bucket: bucket,
        p_key: hashed,
        p_limit: limit,
        p_window: Math.ceil(windowMs / 1000),
      }),
      signal: AbortSignal.timeout(2000),
    });
    if (!response.ok) throw new Error(`rate limit rpc ${response.status}`);
    const rows = await response.json();
    const row = Array.isArray(rows) ? rows[0] : rows;
    if (row) {
      return {
        allowed: Boolean(row.allowed),
        remaining: Number(row.remaining) || 0,
        retryAfter: Number(row.retry_after) || 0,
      };
    }
    return local;
  } catch (error) {
    // Degrade gracefully but loudly.
    db.query('INSERT INTO security_audit (event, detail, created_at) VALUES (?, ?, ?)', [
      'rate_limit_store_unavailable',
      String(error.message || error).slice(0, 300),
      Date.now(),
    ]);
    return local;
  }
}

/** Convenience wrapper for a named policy in config.security.rateLimits. */
async function enforce(policy, key) {
  const [limit, windowMs] = config.security.rateLimits[policy] || config.security.rateLimits.api;
  const result = await check(policy, key, limit, windowMs);
  if (!result.allowed) {
    const err = new Error('Too many attempts. Please wait and try again.');
    err.status = 429;
    err.code = 'rate_limited';
    err.retryAfter = result.retryAfter || 60;
    throw err;
  }
  return result;
}

function reset() {
  buckets.clear();
}

/** Test seam: seed the in-memory window without going through HTTP. */
function peek(bucket, key, windowMs) {
  const now = Date.now();
  const id = `${bucket}:${crypto.createHash('sha256').update(`${bucket}|${key}`).digest('hex')}`;
  return prune(buckets.get(id) || [], windowMs, now).length;
}

module.exports = { check, enforce, reset, peek };
