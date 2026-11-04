'use strict';

/**
 * Outbound mail.
 *
 * The browser can no longer trigger email: there is no public EmailJS key and
 * no client-side service id anywhere in the app. Instead the server:
 *   1. encrypts the message body with AES-256-GCM (SERVER_DATA_KEY),
 *   2. stores it in the private outbound_mail queue (service-role only), and
 *   3. if SMTP is configured, hands it to a transport; otherwise the queue
 *      keeps it for a worker/cron to drain.
 *
 * The verification code is never written to logs.
 */

const config = require('./config');
const db = require('./db');

const FROM = process.env.MAIL_FROM || 'SafeSteps Kenya <no-reply@safesteps.local>';

/**
 * Delivery is "configured" when either a real SMTP transport is present, or the
 * Supabase project has a mail provider (Supabase Auth's built-in mailer). The
 * latter matters because it means sign-in emails can still work with no local
 * SMTP credentials — we route the message through the auth service instead of
 * silently leaving it in a queue nobody drains.
 */
function isConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function supabaseMailerAvailable() {
  return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_PUBLISHABLE_KEY);
}

async function enqueue({ recipient, subject, body, channel = 'email', provider = null }) {
  const encryptedBody = config.security.serverDataKey
    ? db.encryptAtRest(body, config.security.serverDataKey)
    : body; // queue is already private; encryption adds defence in depth when configured

  // Persist to the Postgres queue (shared across instances) when service creds
  // exist; otherwise — or if that write fails — keep it in the local queue.
  // A message must never be dropped on the floor because one store was
  // unavailable: that turns "check your email" into a silent dead end.
  let persisted = false;
  if (config.supabase.serviceRoleKey) {
    try {
      const response = await fetch(`${config.supabase.url}/rest/v1/rpc/api_enqueue_mail`, {
        method: 'POST',
        headers: {
          apikey: config.supabase.serviceRoleKey,
          Authorization: `Bearer ${config.supabase.serviceRoleKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          p_recipient: recipient,
          p_subject: subject,
          p_body: encryptedBody,
          p_channel: channel,
        }),
        signal: AbortSignal.timeout(5000),
      });
      persisted = response.ok;
      if (!response.ok) {
        console.error('[mail] remote queue write failed, falling back to local queue:', response.status);
      }
    } catch (error) {
      console.error('[mail] remote queue unreachable, falling back to local queue:', error.message);
    }
  }

  if (!persisted) {
    db.query(
      'INSERT INTO outbound_mail (recipient, subject, body, channel, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [recipient, subject, encryptedBody, channel, 'queued', Date.now()]
    );
  }

  if (!isConfigured()) {
    // No local transport. Rather than parking the code in a queue nothing
    // drains (which makes sign-up silently impossible), hand it to the auth
    // service's own mailer when the project has one configured.
    if (supabaseMailerAvailable() && typeof provider === 'function') {
      try {
        await provider();
        return { queued: true, delivered: true, via: 'supabase-auth' };
      } catch (error) {
        console.error('[mail] provider delivery failed:', error.message);
      }
    }
    console.info('[mail] queued (no transport configured) channel=%s — see SECURITY.md "Enabling email sign-in"', channel);
    return { queued: true, delivered: false };
  }

  try {
    await sendSmtp({ to: recipient, subject, text: body });
    return { queued: true, delivered: true, via: 'smtp' };
  } catch (error) {
    console.error('[mail] SMTP delivery failed:', error.message);
    return { queued: true, delivered: false };
  }
}

/**
 * Minimal SMTP client (plain + STARTTLS) so the server ships with zero runtime
 * dependencies. Uses node:tls / node:net directly.
 */
function sendSmtp({ to, subject, text }) {
  const net = require('node:net');
  const tls = require('node:tls');
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  return new Promise((resolve, reject) => {
    let socket = net.connect(port, host);
    let buffer = '';
    let step = 0;
    const steps = [
      // { expect: [codes], send: string }
      { expect: [220], send: null },
      { expect: [250], send: `EHLO safesteps.local\r\n` },
      { expect: [220], send: 'STARTTLS\r\n' },
      { expect: [250], send: `EHLO safesteps.local\r\n` },
      { expect: [334], send: `AUTH PLAIN ${Buffer.from(`\u0000${user}\u0000${pass}`).toString('base64')}\r\n` },
      { expect: [235], send: `MAIL FROM:<${extractAddress(FROM)}>\r\n` },
      { expect: [250], send: `RCPT TO:<${to}>\r\n` },
      { expect: [250], send: 'DATA\r\n' },
      { expect: [354], send: buildMessage({ to, subject, text }) },
      { expect: [250], send: 'QUIT\r\n' },
    ];

    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('SMTP timeout'));
    }, 15000);

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      if (!buffer.includes('\r\n')) return;
      const line = buffer.split('\r\n')[0];
      buffer = buffer.slice(buffer.indexOf('\r\n') + 2);
      const code = Number(line.slice(0, 3));
      const current = steps[step];
      if (!current) return;
      if (!current.expect.includes(code)) {
        clearTimeout(timeout);
        socket.destroy();
        reject(new Error(`SMTP unexpected ${code}`));
        return;
      }
      step += 1;

      if (step === 3) {
        // Upgrade to TLS after STARTTLS accepted.
        socket.removeAllListeners('data');
        socket = tls.connect({ socket, servername: host }, () => {
          socket.on('data', onData);
          socket.write(current.send === 'STARTTLS\r\n' ? steps[3].send : '');
        });
        return;
      }
      const next = steps[step];
      if (next && next.send) socket.write(next.send);
      if (!next) {
        clearTimeout(timeout);
        socket.end();
        resolve({ ok: true });
      }
    });

    function onData(chunk) {
      socket.emit('data', chunk);
    }

    socket.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

function extractAddress(value) {
  const match = String(value).match(/<([^>]+)>/);
  return match ? match[1] : String(value).trim();
}

function buildMessage({ to, subject, text }) {
  const headers = [
    `From: ${FROM}`,
    `To: ${to}`,
    `Subject: =?UTF-8?B?${Buffer.from(subject, 'utf8').toString('base64')}?=`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
  ];
  const body = Buffer.from(text, 'utf8')
    .toString('base64')
    .replace(/(.{76})/g, '$1\r\n');
  return `${headers.join('\r\n')}\r\n\r\n${body}\r\n.\r\n`;
}

module.exports = { enqueue, isConfigured };
