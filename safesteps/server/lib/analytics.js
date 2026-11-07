'use strict';

/**
 * Analytics and error monitoring.
 *
 * Section E: "install analytics" and "monitor errors" — without adding a
 * third-party tracker, and without re-introducing the privacy problem that a
 * road-safety app used by schoolchildren should not have.
 *
 * DESIGN CONSTRAINTS, in order of importance
 *
 * 1. **No personal data.** Events record what happened, never who it happened
 *    to. There is no user id, no session id, no IP address, no email, no free
 *    text, and no device fingerprint. The only identity-ish field is a coarse
 *    "is the caller signed in" boolean.
 *
 * 2. **No cookies and no third-party script.** The client sends events to our
 *    own origin, where the server owns them. Nothing is loaded from an
 *    analytics vendor, so there is nothing for the CSP to allow and nothing to
 *    update in the privacy policy beyond describing this.
 *
 * 3. **Buffered and bounded.** Events are aggregated in memory and flushed in
 *    batches. A traffic spike must not turn into a write per request, and the
 *    buffer must never grow without limit — an unbounded queue in a monitoring
 *    path is how monitoring takes down the app it is watching.
 *
 * 4. **Failures here are never the user's problem.** Every write is best-effort
 *    and swallowed. Analytics that can throw during a request is a bug.
 *
 * STORAGE
 *   Postgres path: `public.app_events` (see the migration) through PostgREST
 *   with the service-role key, so no RLS policy has to allow an anonymous
 *   insert. Local/standalone path: the `analytics_events` SQLite table.
 *
 * WHY THE EVENT SHAPE IS A CLOSED LIST
 * Only these event names and these fields are accepted. An endpoint that stores
 * arbitrary JSON from the browser is a data-protection incident waiting for a
 * curious user; this one cannot store anything that is not named below.
 */

const db = require('./db');

const FLUSH_INTERVAL_MS = 15_000;
const MAX_BUFFER = 500;

/**
 * The complete set of things we count. Adding an event means adding it here —
 * there is no "send anything" path.
 */
const EVENTS = Object.freeze({
  app_open: ['outcome'],
  screen_view: ['screen'],
  signup_start: [],
  signup_success: ['outcome'],
  signup_fail: ['reason'],
  login_success: [],
  login_fail: ['reason'],
  password_reset_request: ['outcome'],
  password_reset_complete: ['outcome'],
  report_submit: ['outcome', 'category'],
  quiz_complete: ['outcome'],
  offline_use: ['outcome'],
  api_error: ['route', 'status'],
  client_error: ['kind'],
  account_delete: ['outcome'],
  // Bug reporting. `kind` is the clamped error class, `screen` is the screen id,
  // and `severity` is one of a fixed set. Crucially there is still NO free text
  // here: the user's description is stored by the bug-report table, not mixed
  // into analytics, so this table stays free of anything a person typed.
  bug_report: ['kind', 'screen', 'severity', 'source'],
  error_boundary: ['kind', 'screen'],
});

/** Field values are from a closed vocabulary too, where a vocabulary exists. */

/**
 * Fields whose value must come from a fixed set.
 *
 * For bug reports this matters: a `severity` of "urgent!!! my number is 0712..."
 * is someone typing into a field, and it must not reach storage. Anything not in
 * the list is stored as null rather than rejected outright, so the rest of the
 * report still arrives.
 */
const ENUMS = Object.freeze({
  severity: ['low', 'medium', 'high', 'crash'],
  source: ['automatic', 'manual'],
  kind: ['network', 'javascript', 'storage', 'permission', 'other', 'timeout', 'render'],
});

/** A screen id: the app's own vocabulary, nothing user-supplied. */
function sanitizeScreen(value) {
  const text = String(value === undefined || value === null ? '' : value);
  return /^[a-z][a-z0-9-]{0,31}$/.test(text) ? text : null;
}

const buffer = [];
let dropped = 0;
let lastFlushAt = 0;
let flushTimer = null;
let flushing = false;

/** Counters available for /healthz and /api/metrics without a database. */
const counters = {
  startedAt: Date.now(),
  accepted: 0,
  rejected: 0,
  dropped: 0,
  flushed: 0,
  flushFailures: 0,
  byName: {},
};

function sanitize(value, max = 64) {
  if (value === undefined || value === null) return null;
  const text = String(value);
  // Only short, structured tokens get through. Route paths need "/" (this
  // pattern rejected "/api/auth/login" until a test caught it), and nothing
  // else outside this set survives — no spaces, so no free text.
  if (!/^[A-Za-z0-9_./:-]{1,64}$/.test(text)) return null;
  // Belt and braces: an @ never appears in a legitimate token, and a scheme
  // means someone is trying to smuggle a URL in.
  if (text.includes('@') || text.includes('//')) return null;
  return text.slice(0, max);
}

/**
 * Record one event. Returns true when accepted.
 *
 * @param {string} name  must be a key of EVENTS
 * @param {object} fields only the fields declared for that event
 */
function record(name, fields = {}) {
  // hasOwnProperty, not `EVENTS[name]`: with a plain object, a name like
  // "__proto__" or "constructor" resolves through the prototype chain and is
  // truthy, which crashed the field loop. A name from the browser must never be
  // able to reach anything but this closed list.
  const allowed = Object.prototype.hasOwnProperty.call(EVENTS, name) ? EVENTS[name] : null;
  if (!Array.isArray(allowed)) {
    counters.rejected += 1;
    return false;
  }

  const clean = {};
  for (const field of allowed) {
    if (ENUMS[field]) {
      const value = String(fields[field] === undefined || fields[field] === null ? '' : fields[field]);
      clean[field] = ENUMS[field].includes(value) ? value : null;
    } else if (field === 'screen') {
      clean[field] = sanitizeScreen(fields[field]);
    } else {
      clean[field] = sanitize(fields[field]);
    }
  }

  if (buffer.length >= MAX_BUFFER) {
    // Drop the oldest rather than grow. Losing an analytics row is acceptable;
    // growing without bound is not.
    buffer.shift();
    dropped += 1;
    counters.dropped += 1;
  }

  buffer.push({ name, fields: clean, at: Date.now() });
  counters.accepted += 1;
  counters.byName[name] = (counters.byName[name] || 0) + 1;
  return true;
}

/** Drain the buffer into storage. Never throws. */
async function flush({ force = false } = {}) {
  if (flushing) return { flushed: 0 };
  if (!buffer.length) return { flushed: 0 };
  if (!force && Date.now() - lastFlushAt < 1000) return { flushed: 0 };

  flushing = true;
  const batch = buffer.splice(0, buffer.length);
  try {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (url && key) {
      const response = await fetch(`${url.replace(/\/+$/, '')}/rest/v1/app_events`, {
        method: 'POST',
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify(
          batch.map((e) => ({
            name: e.name,
            fields: e.fields,
            occurred_at: new Date(e.at).toISOString(),
          }))
        ),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error(`app_events insert ${response.status}`);
    } else {
      for (const e of batch) {
        db.query('INSERT INTO analytics_events (name, fields, created_at) VALUES (?, ?, ?)', [
          e.name,
          JSON.stringify(e.fields),
          e.at,
        ]);
      }
    }

    counters.flushed += batch.length;
    lastFlushAt = Date.now();
    return { flushed: batch.length };
  } catch (error) {
    counters.flushFailures += 1;
    // Put them back, but never let the buffer exceed its cap.
    for (const e of batch.reverse()) {
      if (buffer.length < MAX_BUFFER) buffer.unshift(e);
      else dropped += 1;
    }
    console.warn('[analytics] flush failed (kept for retry):', String(error.message || error).slice(0, 160));
    return { flushed: 0, error: true };
  } finally {
    flushing = false;
  }
}

function start() {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    flush().catch(() => {});
  }, FLUSH_INTERVAL_MS);
  // Do not hold the process open just to flush analytics.
  if (flushTimer.unref) flushTimer.unref();
}

function stop() {
  if (flushTimer) clearInterval(flushTimer);
  flushTimer = null;
  return flush({ force: true });
}

/** Snapshot for /healthz and /api/metrics. */
function snapshot() {
  return {
    uptimeSeconds: Math.round((Date.now() - counters.startedAt) / 1000),
    accepted: counters.accepted,
    rejected: counters.rejected,
    dropped: counters.dropped,
    flushed: counters.flushed,
    flushFailures: counters.flushFailures,
    buffered: buffer.length,
    byName: { ...counters.byName },
  };
}

function reset() {
  buffer.length = 0;
  dropped = 0;
  counters.accepted = 0;
  counters.rejected = 0;
  counters.dropped = 0;
  counters.flushed = 0;
  counters.flushFailures = 0;
  counters.byName = {};
}

module.exports = { EVENTS, record, flush, start, stop, snapshot, reset, MAX_BUFFER };
