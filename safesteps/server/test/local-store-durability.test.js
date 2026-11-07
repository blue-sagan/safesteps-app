'use strict';

/**
 * Is the local store durable?
 *
 * SQLite's default is ':memory:', and a write to an in-memory database succeeds
 * exactly like a write to a file. That symmetry is what made a real defect
 * invisible: the bug-report fallback wrote to ':memory:', got no error, replied
 * 201 "recorded", and the row was gone at the next restart.
 *
 * So the durability question has to be answerable separately from "did the write
 * succeed". These tests pin the answer for every form the configuration can
 * take, because getting it wrong in either direction is a bug:
 *
 *   saying volatile when durable  -> a report that WAS kept is reported as lost,
 *                                   and the reporter re-sends needlessly
 *   saying durable when volatile  -> a report that was LOST is reported as kept,
 *                                   and nobody ever finds out
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const db = require('../lib/db');

function withPath(value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, 'SQLITE_PATH');
  const previous = process.env.SQLITE_PATH;
  try {
    if (value === undefined) delete process.env.SQLITE_PATH;
    else process.env.SQLITE_PATH = value;
    return fn();
  } finally {
    if (had) process.env.SQLITE_PATH = previous;
    else delete process.env.SQLITE_PATH;
  }
}

test('unset SQLITE_PATH is volatile, because SQLite defaults to :memory:', () => {
  withPath(undefined, () => {
    assert.equal(db.isMemoryBacked(), true,
      'an unset path must be treated as RAM — this is the exact production case that lost reports');
  });
});

test('the explicit :memory: form is volatile', () => {
  withPath(':memory:', () => assert.equal(db.isMemoryBacked(), true));
});

test('an empty SQLITE_PATH is volatile rather than a relative file', () => {
  // '' is falsy, so `file || ':memory:'` already picks RAM. Assert the helper
  // agrees with that, instead of treating '' as a filename.
  withPath('', () => assert.equal(db.isMemoryBacked(), true));
});

test('a shared-cache memory URI is volatile', () => {
  withPath('file::memory:?cache=shared', () => assert.equal(db.isMemoryBacked(), true));
  withPath('file:whatever?mode=memory&cache=shared', () => assert.equal(db.isMemoryBacked(), true));
});

test('a real file path is durable', () => {
  withPath('/var/data/safesteps.db', () => assert.equal(db.isMemoryBacked(), false));
  withPath('./local.db', () => assert.equal(db.isMemoryBacked(), false));
  // A filename that merely CONTAINS 'memory' is still a file on disk.
  withPath('/var/data/memory.db', () => assert.equal(db.isMemoryBacked(), false),
    'matching on the substring would wrongly label a durable file volatile');
});

test('the helper never throws, whatever the environment looks like', () => {
  // It is called on the failure path, where things are already going wrong. A
  // throw here would turn "cannot save the report" into "the request died".
  for (const value of [undefined, '', ':memory:', 'file::memory:', '/tmp/x.db', ':::', '\u0000odd']) {
    withPath(value, () => {
      assert.doesNotThrow(() => db.isMemoryBacked(), `threw for ${JSON.stringify(value)}`);
      assert.equal(typeof db.isMemoryBacked(), 'boolean');
    });
  }
});

test('when the local store is available, a write to it still succeeds — success is not durability', () => {
  // The premise of the whole fix: an insert into a volatile store returns no
  // error, so "the write succeeded" can never be used as evidence that the data
  // was kept.
  //
  // `node:sqlite` shipped in Node 22; the server's declared engine floor is
  // Node 20, where the store is simply unavailable. Both runtimes are in the CI
  // matrix, so this asserts whichever situation applies rather than assuming one.
  withPath(undefined, () => {
    if (!db.isAvailable()) {
      // Node 20 floor: no local store at all. isMemoryBacked() is still correct
      // because it answers from configuration alone, which is the point — the
      // caller must be able to ask the question even when nothing works.
      assert.equal(db.isMemoryBacked(), true,
        'with no store available, the answer must still be "not durable"');
      assert.throws(() => db.query('SELECT 1'), db.LocalStoreUnavailable,
        'a missing runtime dependency must surface as LocalStoreUnavailable');
      return;
    }
    assert.equal(db.isMemoryBacked(), true, 'the fallback store is volatile');
    assert.doesNotThrow(() => {
      db.query('CREATE TABLE IF NOT EXISTS durability_probe (id INTEGER PRIMARY KEY, v TEXT)');
      db.query('INSERT INTO durability_probe (v) VALUES (?)', ['written']);
    }, 'the insert into RAM succeeds without error — success is not durability');
  });
});
