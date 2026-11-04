/* ============================================================================
   SafeSteps — client security module  (assets/security.js)
   ----------------------------------------------------------------------------
   This file is the ONLY place the PWA talks to the network for account data.

   What changed versus the old build:
     • There is no API key of any kind here. The browser receives the Supabase
       *publishable* key from GET /api/config at runtime, and every account
       write goes through the SafeSteps server, which re-authenticates, re-
       validates and rate-limits it.
     • No password is ever hashed, stored or echoed in the client. Passwords go
       straight to the server over TLS, which hands them to the auth service
       (bcrypt). Nothing password-shaped is written to localStorage.
     • Session tokens live in HttpOnly cookies. JavaScript cannot read them, so
       an XSS payload cannot exfiltrate a session.
     • All state-changing calls send the double-submit CSRF token.
     • Sensitive payloads (the local vault, whistleblower narratives) are
       encrypted with AES-256-GCM *before* they leave the device, using a key
       derived from the user's password with PBKDF2-SHA256. The server and the
       database only ever see ciphertext.
   ============================================================================ */
(function (global) {
  'use strict';

  const SS = global.SS || (global.SS = {});

  /* ------------------------------------------------------------------ */
  /* Small, strict input helpers (server validates again — always).      */
  /* ------------------------------------------------------------------ */
  const EMAIL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

  // Password length policy. Short by design per product requirement (6–8
  // characters); the strength loss is offset server-side by bcrypt hashing,
  // per-address login throttling and the proof-of-work bot check.
  const PASSWORD_MIN = 6;
  const PASSWORD_MAX = 8;
  SS.PASSWORD_MIN = PASSWORD_MIN;
  SS.PASSWORD_MAX = PASSWORD_MAX;

  SS.input = {
    email(value) {
      const email = String(value || '').trim().toLowerCase();
      if (email.length > 254 || !EMAIL_RE.test(email)) return null;
      return email;
    },
    password(value) {
      // Mirrors server policy (lib/validate.js cleanPassword) so the user gets
      // instant feedback instead of a round trip. Keep the two in step.
      const password = String(value || '');
      if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
        return { ok: false, message: `Use ${PASSWORD_MIN} to ${PASSWORD_MAX} characters.` };
      }
      if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
        return { ok: false, message: 'Include at least one letter and one number.' };
      }
      return { ok: true, value: password };
    },
    text(value, { min = 0, max = 200 } = {}) {
      const text = String(value || '').trim().replace(/\s+/g, ' ');
      if (text.length < min || text.length > max) return null;
      return text;
    },
    code(value) {
      const code = String(value || '').replace(/\s/g, '');
      return /^[0-9]{8}$/.test(code) ? code : null;
    },
  };

  /* ------------------------------------------------------------------ */
  /* Output escaping — used by every render path that touches innerHTML. */
  /* ------------------------------------------------------------------ */
  SS.escapeHtml = function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"'`/]/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;', '/': '&#47;',
    }[ch]));
  };

  /** Only permit http(s) links; blocks javascript:/data:/vbscript: vectors. */
  SS.safeUrl = function safeUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return '';
    try {
      const url = new URL(raw, global.location.origin);
      return /^(https?:|mailto:|tel:)$/.test(url.protocol) ? url.href : '';
    } catch {
      return '';
    }
  };

  /* ------------------------------------------------------------------ */
  /* CSRF token (readable by design, must be echoed in a header).        */
  /* ------------------------------------------------------------------ */
  function readCookie(name) {
    const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
    return match ? decodeURIComponent(match[1]) : null;
  }

  SS.csrfToken = function csrfToken() {
    return readCookie('__Host-ss_csrf') || readCookie('ss_csrf') || null;
  };

  /* ------------------------------------------------------------------ */
  /* API client                                                         */
  /* ------------------------------------------------------------------ */
  class ApiError extends Error {
    constructor(message, { status, code, fields } = {}) {
      super(message);
      this.name = 'ApiError';
      this.status = status || 0;
      this.code = code || 'request_failed';
      this.fields = fields || null;
    }
  }
  SS.ApiError = ApiError;

  async function api(pathname, { method = 'GET', body, headers = {}, timeout = 20000 } = {}) {
    const init = {
      method,
      credentials: 'same-origin', // cookies are HttpOnly + SameSite=Strict
      headers: { Accept: 'application/json', ...headers },
      signal: AbortSignal.timeout(timeout),
    };

    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    if (method !== 'GET') {
      const token = SS.csrfToken();
      if (token) init.headers['X-CSRF-Token'] = token;
    }

    let response;
    try {
      response = await fetch(pathname, init);
    } catch (error) {
      throw new ApiError('You appear to be offline. SafeSteps saved nothing that could be lost — try again when you reconnect.', {
        status: 0,
        code: 'network_unavailable',
      });
    }

    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }

    if (!response.ok) {
      throw new ApiError(
        (payload && payload.message) || 'That request could not be completed.',
        { status: response.status, code: (payload && payload.error) || 'request_failed', fields: payload && payload.fields }
      );
    }
    return payload;
  }
  SS.api = api;

  /* ------------------------------------------------------------------ */
  /* Bot protection: solve the server's proof-of-work challenge.        */
  /* Cheap for a person (a few hundred ms), expensive at scale.          */
  /* ------------------------------------------------------------------ */
  let challengeCache = null;

  async function fetchChallenge() {
    if (challengeCache && challengeCache.expiresAt > Date.now()) return challengeCache;
    const issued = await api('/api/auth/challenge');
    challengeCache = {
      challenge: issued.challenge,
      difficulty: issued.difficulty || 4,
      expiresAt: Date.now() + Math.max(30, (issued.expiresInSeconds || 300) - 30) * 1000,
    };
    return challengeCache;
  }

  function toHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  async function solveProofOfWork(challenge, difficulty) {
    const encoder = new TextEncoder();
    const salt = challenge.split('.')[0];
    for (let nonce = 0; nonce < 5_000_000; nonce += 1) {
      const digest = await global.crypto.subtle.digest('SHA-256', encoder.encode(`${salt}:${nonce}`));
      const hex = toHex(digest);
      let zeros = 0;
      for (const char of hex) {
        if (char !== '0') break;
        zeros += 1;
      }
      if (zeros >= difficulty) return String(nonce);
    }
    throw new ApiError('Could not complete the security check. Please reload the app.', { code: 'bot_solve_failed' });
  }

  /** Returns { botChallenge, botNonce } to merge into a sensitive request body. */
  SS.botProof = async function botProof() {
    if (!global.crypto || !global.crypto.subtle) return {}; // server still enforces its own limits
    const { challenge, difficulty } = await fetchChallenge();
    const nonce = await solveProofOfWork(challenge, difficulty);
    return { botChallenge: challenge, botNonce: nonce };
  };

  SS.resetBotChallenge = function resetBotChallenge() {
    challengeCache = null;
  };

  /* ------------------------------------------------------------------ */
  /* Crypto: PBKDF2 key derivation + AES-256-GCM                        */
  /* ------------------------------------------------------------------ */
  const subtle = global.crypto && global.crypto.subtle ? global.crypto.subtle : null;
  const PBKDF2_ITERATIONS = 310000; // OWASP 2023+ guidance for PBKDF2-HMAC-SHA256

  function toBase64(bytes) {
    let binary = '';
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
    return global.btoa(binary);
  }

  function fromBase64(value) {
    const binary = global.atob(String(value));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  SS.crypto = {
    // Exposed so callers that build their own envelopes can record the exact
    // work factor used, instead of hard-coding a number that can drift.
    PBKDF2_ITERATIONS,

    available() {
      return Boolean(subtle);
    },

    randomBytes(length = 32) {
      const bytes = new Uint8Array(length);
      global.crypto.getRandomValues(bytes);
      return bytes;
    },

    async deriveKey(password, saltBytes, iterations = PBKDF2_ITERATIONS) {
      const material = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
      return subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    },

    async encryptString(key, plaintext) {
      const iv = SS.crypto.randomBytes(12);
      const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(String(plaintext)));
      return { ciphertext: toBase64(ciphertext), iv: toBase64(iv) };
    },

    async decryptString(key, ciphertextB64, ivB64) {
      const plaintext = await subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(ivB64) },
        key,
        fromBase64(ciphertextB64)
      );
      return new TextDecoder().decode(plaintext);
    },
  };

  /**
   * Envelope encryption for the user vault.
   * A random 256-bit data key encrypts the payload; that data key is wrapped
   * with a password-derived key. Changing the password only re-wraps the key,
   * and the database never holds anything but ciphertext.
   */
  SS.vault = {
    async seal(password, payload) {
      if (!SS.crypto.available()) throw new ApiError('This browser cannot encrypt your vault (Web Crypto unavailable).');
      const salt = SS.crypto.randomBytes(16);
      const kdfKey = await SS.crypto.deriveKey(password, salt);
      const dataKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

      const body = await SS.crypto.encryptString(dataKey, JSON.stringify(payload));
      const rawDataKey = await subtle.exportKey('raw', dataKey);
      const wrapped = await SS.crypto.encryptString(kdfKey, toBase64(rawDataKey));

      return {
        kdfSalt: toBase64(salt),
        kdfIterations: PBKDF2_ITERATIONS,
        wrappedKey: wrapped.ciphertext,
        wrappedKeyIv: wrapped.iv,
        ciphertext: body.ciphertext,
        iv: body.iv,
        version: 1,
      };
    },

    async unseal(password, record) {
      const kdfKey = await SS.crypto.deriveKey(password, fromBase64(record.kdfSalt), record.kdfIterations);
      const rawDataKey = await SS.crypto.decryptString(kdfKey, record.wrappedKey, record.wrappedKeyIv);
      const dataKey = await subtle.importKey('raw', fromBase64(rawDataKey), 'AES-GCM', false, ['encrypt', 'decrypt']);
      return JSON.parse(await SS.crypto.decryptString(dataKey, record.ciphertext, record.iv));
    },

    async save(password, payload) {
      const sealed = await SS.vault.seal(password, payload);
      await api('/api/vault', { method: 'POST', body: sealed });
      return sealed;
    },

    async load(password) {
      const me = await api('/api/auth/me');
      if (!me || !me.user) throw new ApiError('Please sign in first.', { status: 401 });
      return me.user;
    },
  };

  /** Encrypts a whistleblower narrative locally; returns ciphertext fields. */
  SS.encryptNarrative = async function encryptNarrative(password, narrative) {
    const salt = SS.crypto.randomBytes(16);
    const key = await SS.crypto.deriveKey(password, salt);
    const sealed = await SS.crypto.encryptString(key, narrative);
    return { narrative_ciphertext: sealed.ciphertext, narrative_iv: sealed.iv, narrative_salt: toBase64(salt) };
  };

  /* ------------------------------------------------------------------ */
  /* Whistleblower dossier encryption                                   */
  /* ------------------------------------------------------------------ */
  /**
   * The narrative is encrypted on the device with an AES-256-GCM key that is
   * generated once, stored in IndexedDB as a NON-EXTRACTABLE CryptoKey, and
   * never leaves the device. The server therefore receives ciphertext it
   * cannot read, and the ciphertext is useless to anyone who steals a database
   * dump without the physical device.
   */
  const IDB_NAME = 'safesteps-keys';
  const IDB_STORE = 'dossier';

  function openKeyDb() {
    return new Promise((resolve, reject) => {
      const request = global.indexedDB.open(IDB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(IDB_STORE)) {
          request.result.createObjectStore(IDB_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function getDeviceKey() {
    if (!global.indexedDB || !subtle) throw new ApiError('This browser cannot encrypt evidence on device.');
    const database = await openKeyDb();
    const read = () => new Promise((resolve, reject) => {
      const tx = database.transaction(IDB_STORE, 'readonly');
      const request = tx.objectStore(IDB_STORE).get('dossier-key');
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });

    const existing = await read();
    if (existing && existing.key) return existing;

    const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const record = { key, id: SS.crypto.randomBytes(16) };
    await new Promise((resolve, reject) => {
      const tx = database.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(record, 'dossier-key');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    return record;
  }

  SS.dossier = {
    /** Encrypt a narrative for upload. Returns the columns the API expects. */
    async encrypt(narrative) {
      const record = await getDeviceKey();
      const sealed = await SS.crypto.encryptString(record.key, narrative);
      return {
        narrative_ciphertext: sealed.ciphertext,
        narrative_iv: sealed.iv,
        // Opaque device-key id; lets the app tell which device can decrypt.
        narrative_salt: toBase64(record.id),
      };
    },
  };

  /* ------------------------------------------------------------------ */
  /* Session bootstrap                                                  */
  /* ------------------------------------------------------------------ */
  SS.session = {
    async config() {
      if (!SS._config) SS._config = await api('/api/config');
      return SS._config;
    },
    /**
     * Which server-backed features this deployment actually has. The UI uses
     * this to disable what cannot work and say why, instead of showing a button
     * that always fails. Offline features never depend on it.
     */
    async capabilities() {
      try {
        const cfg = await SS.session.config();
        return cfg.capabilities || { auth: true, emailVerification: true, atRestEncryption: true };
      } catch {
        return { auth: false, emailVerification: false, atRestEncryption: false, offline: true };
      }
    },
    async me() {
      try {
        return await api('/api/auth/me');
      } catch (error) {
        if (error.status === 401) return null;
        throw error;
      }
    },
    login: (email, password, bot) => api('/api/auth/login', { method: 'POST', body: { email, password, ...bot } }),
    register: (payload, bot) => api('/api/auth/register', { method: 'POST', body: { ...payload, ...bot } }),
    verify: (email, code, bot) => api('/api/auth/verify', { method: 'POST', body: { email, code, ...bot } }),
    resend: (email, bot) => api('/api/auth/resend', { method: 'POST', body: { email, ...bot } }),
    logout: () => api('/api/auth/logout', { method: 'POST', body: {} }),
  };

  /* ------------------------------------------------------------------ */
  /* Uploads                                                            */
  /* ------------------------------------------------------------------ */
  /**
   * Send one file to the server's validated upload endpoint.
   *
   * The server (lib/uploads.js) sniffs the leading bytes rather than trusting
   * what we claim, so the browser cannot widen the allow-list. The file travels
   * as a raw body with its type in headers — no multipart parser, so there is
   * no parser to exploit — and the response is the trimmed
   * `{path, mime, bytes, sha256}` the caller can reference later.
   */
  SS.uploads = {
    MAX_BYTES: 8 * 1024 * 1024,
    ALLOWED: ['image/jpeg', 'image/png', 'image/webp', 'audio/webm', 'audio/mpeg', 'video/mp4', 'video/webm'],

    /** Local pre-flight so an obviously wrong file never leaves the device. */
    check(file) {
      if (!file) return { ok: false, message: 'No file selected.' };
      if (file.size > this.MAX_BYTES) {
        return { ok: false, message: `That file is too large (${(file.size / 1048576).toFixed(1)} MB). The limit is 8 MB.` };
      }
      if (this.ALLOWED.indexOf(file.type) === -1) {
        return { ok: false, message: 'Only JPEG/PNG/WebP photos, WebM/MP3 audio or MP4/WebM video can be attached.' };
      }
      return { ok: true };
    },

    async upload(file, { timeout = 30000 } = {}) {
      const verdict = this.check(file);
      if (!verdict.ok) throw new ApiError(verdict.message, { code: 'invalid_upload' });

      const response = await fetch('/api/uploads', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': file.type,
          'X-File-Name': encodeURIComponent(file.name || 'evidence'),
          'X-CSRF-Token': SS.csrfToken() || '',
        },
        body: file,
        signal: AbortSignal.timeout(timeout),
      });

      const text = await response.text();
      let payload = null;
      try {
        payload = text ? JSON.parse(text) : null;
      } catch {
        payload = null;
      }
      if (!response.ok) {
        throw new ApiError(
          (payload && payload.message) || 'That file could not be uploaded.',
          { status: response.status, code: (payload && payload.error) || 'upload_failed' }
        );
      }
      return payload; // { path, mime, bytes, sha256 }
    },
  };

  SS.isOnline = () => global.navigator.onLine !== false;
})(typeof window !== 'undefined' ? window : globalThis);
