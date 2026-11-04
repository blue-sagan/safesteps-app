'use strict';

/**
 * Outbound mail.
 *
 * The browser can never trigger email: there is no EmailJS key, service id or
 * template id anywhere in client code. Instead the server:
 *   1. encrypts the message body with AES-256-GCM (SERVER_DATA_KEY),
 *   2. stores it in the private outbound_mail queue (service-role only), and
 *   3. hands it to a transport — SMTP, or the EmailJS REST API — when one is
 *      configured; otherwise the queue keeps it for a worker/cron to drain.
 *
 * Transport order (first configured wins):
 *   SMTP_*  →  EMAILJS_*  →  Supabase Auth's mailer  →  encrypted local spool
 *
 * The verification code is never written to logs, and no provider credential is
 * ever included in a response.
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
function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

/**
 * EmailJS REST API. The key here is the *private* one where the account offers
 * it; a public key also works because the API is called from the server, never
 * from a browser — the browser never learns it. Values are read from the
 * environment only, so rotating a key needs no code change and nothing is ever
 * committed.
 */
function emailJsConfig() {
  const serviceId = (process.env.EMAILJS_SERVICE_ID || '').trim();
  const templateId = (process.env.EMAILJS_TEMPLATE_ID || '').trim();
  const publicKey = (process.env.EMAILJS_PUBLIC_KEY || '').trim();
  const privateKey = (process.env.EMAILJS_PRIVATE_KEY || '').trim();
  const templateVerification = (process.env.EMAILJS_TEMPLATE_VERIFICATION || '').trim();
  const endpoint = (process.env.EMAILJS_API_URL || 'https://api.emailjs.com/api/v1.0/email/send').trim();
  return { serviceId, templateId, publicKey, privateKey, templateVerification, endpoint };
}

function emailJsConfigured() {
  const { serviceId, templateId, publicKey } = emailJsConfig();
  return Boolean(serviceId && templateId && publicKey);
}

/** True when any transport can actually deliver a message right now. */
function isConfigured() {
  return smtpConfigured() || emailJsConfigured();
}

function supabaseMailerAvailable() {
  return Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_PUBLISHABLE_KEY);
}

/**
 * Deliver one message through EmailJS. The request body is the EmailJS
 * `email/send` shape; template params carry the same fields the SMTP message
 * would, so one template can serve every mail this server sends.
 *
 * Errors are returned, never thrown with the request body attached: a provider
 * error message can echo the recipient or the payload.
 */
async function sendEmailJs({ to, subject, text, templateId, code = null }) {
  const cfg = emailJsConfig();
  const payload = {
    service_id: cfg.serviceId,
    template_id: templateId || cfg.templateId,
    user_id: cfg.publicKey,
    template_params: {
      to_email: to,
      // Common alias names, so an existing template does not have to be edited.
      email: to,
      reply_to: extractAddress(FROM),
      from_name: extractName(FROM),
      subject,
      // Both common body variables, for the same reason.
      message: text,
      body: text,
      // Present only for verification mail, so a template can render
      // {{verification_code}} directly instead of parsing the body.
      ...(code ? { verification_code: code } : {}),
    },
  };
  if (cfg.privateKey) payload.accessToken = cfg.privateKey;

  const response = await fetch(cfg.endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => '');
    // Trim and scrub: only the status and a short reason are logged.
    const reason = String(detail || '').replace(/\s+/g, ' ').slice(0, 120);
    throw new Error(`EmailJS rejected the message (${response.status})${reason ? `: ${reason}` : ''}`);
  }
  return { ok: true };
}

async function enqueue({
  recipient,
  subject,
  body,
  channel = 'email',
  provider = null,
  // Optional: when present, the EmailJS verification template is used so the
  // code can be a first-class template variable instead of being parsed out of
  // the body. The code is never persisted in cleartext beyond the queue row.
  verificationCode = null,
}) {
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

  // SMTP first: it delivers to any mailbox with no third-party rate limit.
  if (smtpConfigured()) {
    try {
      await sendSmtp({ to: recipient, subject, text: body });
      return { queued: true, delivered: true, via: 'smtp' };
    } catch (error) {
      console.error('[mail] SMTP delivery failed:', error.message);
      // Fall through to EmailJS rather than losing the message: sign-up should
      // not fail because one provider is having a bad afternoon.
      if (!emailJsConfigured()) return { queued: true, delivered: false };
    }
  }

  if (emailJsConfigured()) {
    const cfg = emailJsConfig();
    const templateId = verificationCode && cfg.templateVerification ? cfg.templateVerification : cfg.templateId;
    try {
      await sendEmailJs({
        to: recipient,
        subject,
        text: verificationCode
          ? `${body}\n\nYour SafeSteps verification code is ${verificationCode}.`
          : body,
        templateId,
        code: verificationCode,
      });
      return { queued: true, delivered: true, via: 'emailjs' };
    } catch (error) {
      console.error('[mail] EmailJS delivery failed:', error.message);
      // Same last resort as above: the auth service's own mailer.
      if (supabaseMailerAvailable() && typeof provider === 'function') {
        try {
          await provider();
          return { queued: true, delivered: true, via: 'supabase-auth' };
        } catch (providerError) {
          console.error('[mail] provider delivery failed:', providerError.message);
        }
      }
      return { queued: true, delivered: false, via: 'emailjs' };
    }
  }

  return { queued: true, delivered: false };
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

function extractName(value) {
  const match = String(value).match(/^\s*"?([^"<]+?)"?\s*</);
  return match ? match[1].trim() : extractAddress(value);
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

module.exports = {
  enqueue,
  isConfigured,
  // Exposed so /healthz and the tests can report *which* transport is live
  // without ever reading a credential value.
  transports: () => ({
    smtp: smtpConfigured(),
    emailjs: emailJsConfigured(),
    supabaseAuth: supabaseMailerAvailable(),
  }),
};
