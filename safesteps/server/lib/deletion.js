'use strict';

/**
 * Deletion safeguards: caps, typed confirmation and explicit approval.
 *
 * Section 2 of the data-safety brief, enforced where the client cannot reach:
 *
 *   • Restrict bulk deletes     — only the owner's own rows, only two tables.
 *   • Row/record limits         — 10 per request, checked here AND in Postgres.
 *   • Server-side enforcement   — this module is the only path to a delete.
 *   • Impact preview            — count() replies come from the database, never
 *                                from the client's claim about what it selected.
 *   • Typed confirmation        — a high-impact delete needs a phrase typed out.
 *   • Explicit approval         — a destructive run can be held for a second,
 *                                out-of-band approval before it executes.
 *   • Audit logging             — every deletion writes a deletion_audit row,
 *                                including who and when.
 *
 * WHY THE PHRASE IS BUILT HERE, NOT ACCEPTED FROM THE CLIENT
 * If a caller could choose the confirmation phrase, the check would be
 * "did you send the string you sent" — no evidence a human read anything. The
 * server states the phrase in the preview and verifies exactly that phrase.
 *
 * WHY "HIGH IMPACT" IS A THRESHOLD, NOT A BUTTON
 * Asking for a typed phrase on every single-record delete trains people to type
 * it without reading. The phrase is required only at or above the threshold,
 * where the consequence is actually different.
 */

const crypto = require('node:crypto');

/** Hard ceiling per request. The database enforces the same number. */
const MAX_ROWS_PER_REQUEST = 10;

/**
 * At or above this count, the caller must echo a phrase the server generated.
 * Below it, the preview number alone is the confirmation.
 */
const TYPED_CONFIRMATION_THRESHOLD = 3;

/** Tables a user may delete from. Anything else is refused before any query. */
const DELETABLE_TABLES = new Set(['safety_reports', 'integrity_reports']);

class DeletionError extends Error {
  constructor(message, { status = 400, code = 'invalid_deletion', expose = true, fields } = {}) {
    super(message);
    this.name = 'DeletionError';
    this.status = status;
    this.code = code;
    this.expose = expose;
    if (fields) this.fields = fields;
  }
}

/**
 * The phrase for a given table and count. Deterministic, so the preview can
 * state it and the execute call can verify it without storing session state.
 *
 * "delete 7 safety reports" — readable, and impossible to produce by fat-fingering
 * a number into the wrong box.
 */
function confirmationPhrase(table, count) {
  const noun = table === 'safety_reports' ? 'safety report' : 'integrity report';
  return `delete ${count} ${noun}${count === 1 ? '' : 's'}`;
}

function phraseRequired(count) {
  return count >= TYPED_CONFIRMATION_THRESHOLD;
}

/**
 * Emptying the bin always needs a typed phrase, even for one item.
 *
 * A soft delete is recoverable for 30 days, so a phrase there is a speed bump
 * for the case that actually matters — a large wipe. A purge has no undo path
 * at all: once the bin entry is gone the record is unrecoverable, whatever the
 * count. Reusing the delete threshold here let a two-item purge slip through
 * with no confirmation, which a test caught and this split fixes.
 */
function purgePhraseRequired(count) {
  return count >= 1;
}

/**
 * Normalise and validate a requested id list.
 *
 * De-duplicates BEFORE the cap is applied, matching the database: sending one id
 * twenty times is one record and must not be rejected by a cap meant for twenty
 * distinct records. Refuses anything that is not a UUID rather than letting the
 * database raise a type error, so the message stays useful.
 */
function normaliseIds(input) {
  if (!Array.isArray(input)) {
    throw new DeletionError('Selected records must be a list.', { fields: { ids: 'Must be a list.' } });
  }
  const seen = new Set();
  for (const raw of input) {
    if (typeof raw !== 'string') {
      throw new DeletionError('One of the selected records is not a valid id.', {
        fields: { ids: 'Ids must be strings.' },
      });
    }
    const id = raw.trim().toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
      throw new DeletionError('One of the selected records is not a valid id.', {
        fields: { ids: 'Each id must be a UUID.' },
      });
    }
    seen.add(id);
  }
  const ids = [...seen];
  if (ids.length === 0) {
    throw new DeletionError('Select at least one record.', { fields: { ids: 'Nothing selected.' } });
  }
  if (ids.length > MAX_ROWS_PER_REQUEST) {
    throw new DeletionError(
      `You can delete at most ${MAX_ROWS_PER_REQUEST} records at a time. You selected ${ids.length}.`,
      { status: 413, code: 'too_many_records', fields: { ids: `Maximum ${MAX_ROWS_PER_REQUEST}.` } }
    );
  }
  return ids;
}

function assertDeletableTable(table) {
  if (typeof table !== 'string' || !DELETABLE_TABLES.has(table)) {
    throw new DeletionError('That kind of record cannot be deleted here.', {
      status: 400,
      code: 'unsupported_table',
      fields: { table: 'Unsupported record type.' },
    });
  }
  return table;
}

/**
 * Verify the typed phrase for a delete that found `matched` real rows.
 *
 * Called after the preview, with the *matched* count rather than the requested
 * count: the phrase must describe what is actually about to happen.
 */
function assertPhrase(table, matched, provided) {
  if (!phraseRequired(matched)) return;
  const expected = confirmationPhrase(table, matched);
  if (typeof provided !== 'string' || provided.trim().toLowerCase() !== expected) {
    throw new DeletionError(
      `Type exactly "${expected}" to confirm deleting ${matched} records.`,
      {
        status: 428, // Precondition Required — the request is well formed, the confirmation is missing
        code: 'confirmation_required',
        fields: { confirm: `Type "${expected}".` },
      }
    );
  }
}

/* ------------------------------------------------------------------------- */
/* Explicit approval                                                          */
/* ------------------------------------------------------------------------- */

/**
 * A destructive action can be held for explicit approval.
 *
 * Approval is driven by ONE environment variable, `DELETION_APPROVAL_TOKEN`.
 * When it is set, a delete that reaches `DELETION_APPROVAL_THRESHOLD` records is
 * created as a pending request instead of executing, and the caller must send
 * the token back in a second request. That token must come from somewhere the
 * app cannot reach on its own — a password manager, an ops runbook, a ticketing
 * system.
 *
 * Two honest limits, stated rather than hidden:
 *
 *   1. If the same person holds the token and can sign in, this is a speed bump,
 *      not a second pair of eyes. Real four-eyes control needs a second identity,
 *      which is an organisational arrangement no code can supply.
 *   2. When the token is NOT configured, approval is DISABLED and the log says
 *      exactly that. It does not pretend to be satisfied; a silent "approved"
 *      would be worse than no gate at all.
 *
 * Pending requests are held in memory. A server restart drops them, which is the
 * safe direction: a request nobody approved should not survive to be executed by
 * a later process.
 */
const APPROVAL_THRESHOLD = Number(process.env.DELETION_APPROVAL_THRESHOLD || 5);
const APPROVAL_TTL_MS = 15 * 60 * 1000;
const MAX_PENDING = 200;

const pendingApprovals = new Map();

function approvalToken() {
  return String(process.env.DELETION_APPROVAL_TOKEN || '').trim();
}

function approvalEnabled() {
  return approvalToken().length > 0;
}

function approvalRequired(count) {
  return approvalEnabled() && count >= APPROVAL_THRESHOLD;
}

function approvalStatus() {
  return {
    enabled: approvalEnabled(),
    threshold: APPROVAL_THRESHOLD,
    // Said plainly so the UI can be honest about what is and is not enforced.
    note: approvalEnabled()
      ? `Deletes of ${APPROVAL_THRESHOLD} or more records wait for explicit approval.`
      : 'Explicit approval is not configured on this server. Large deletes are not held.',
  };
}

function sweepPending(now = Date.now()) {
  for (const [id, entry] of pendingApprovals) {
    if (entry.expiresAt <= now) pendingApprovals.delete(id);
  }
  // Bound the map even if nothing expires, so it cannot grow without limit.
  while (pendingApprovals.size > MAX_PENDING) {
    pendingApprovals.delete(pendingApprovals.keys().next().value);
  }
}

function createPendingApproval({ userId, table, ids, matched }) {
  sweepPending();
  const id = crypto.randomUUID();
  pendingApprovals.set(id, {
    id,
    userId,
    table,
    ids,
    matched,
    createdAt: Date.now(),
    expiresAt: Date.now() + APPROVAL_TTL_MS,
  });
  return { id, expiresInSeconds: Math.floor(APPROVAL_TTL_MS / 1000), matched };
}

/**
 * Verify an approval token supplied with a pending request.
 *
 * Compared with a constant-time equality so the token cannot be recovered by
 * timing the response.
 */
function checkApprovalToken(provided) {
  const expected = approvalToken();
  if (!expected) return false;
  if (typeof provided !== 'string' || provided.length === 0) return false;
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    // Still consume comparable work so length is not a free oracle.
    crypto.timingSafeEqual(b, b);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/** Fetch and consume a pending approval. Single-use, owner-bound, time-bound. */
function takePendingApproval(id, userId) {
  sweepPending();
  const entry = pendingApprovals.get(id);
  if (!entry) return null;
  // Bound to the user who created it: an approval id leaking to another account
  // cannot be used to delete their records.
  if (entry.userId !== userId) return null;
  pendingApprovals.delete(id);
  return entry;
}

/** Test seam: drop all pending approvals. */
function _resetPending() {
  pendingApprovals.clear();
}

module.exports = {
  MAX_ROWS_PER_REQUEST,
  TYPED_CONFIRMATION_THRESHOLD,
  DELETABLE_TABLES,
  DeletionError,
  confirmationPhrase,
  phraseRequired,
  purgePhraseRequired,
  normaliseIds,
  assertDeletableTable,
  assertPhrase,
  approvalEnabled,
  approvalRequired,
  approvalStatus,
  createPendingApproval,
  checkApprovalToken,
  takePendingApproval,
  _resetPending,
};
