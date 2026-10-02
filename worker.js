/* HELLO server — Cloudflare Worker
 *
 * What it does:
 *   1. Proves a phone number belongs to a person (texts a 6-digit code).
 *   2. Passes messages from one HELLO phone to another.
 *   3. Deletes each message from the server after the other phone receives it.
 *
 * What it needs:
 *   - A D1 database connected to this Worker with the binding name:  DB
 *
 * Text messages (optional):
 *   If these three secrets are set, real text messages are sent with Twilio Verify:
 *     TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID
 *   If they are NOT set, the server runs in TEST MODE:
 *     no text is sent, and the code is shown on the screen instead.
 *     TEST MODE is for testing only. In TEST MODE anyone can claim any number.
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400'
};
const PHONE = /^\+[1-9]\d{7,14}$/;
const MAX_BODY = 1400000;      // largest single message, in characters
const MAX_WAITING = 200;       // most undelivered messages one person can have
const KEEP_DAYS = 7;           // undelivered messages are deleted after this many days

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
const fail = (status, error) => json({ error }, status);

let tablesReady = false;
async function makeTables(db) {
  if (tablesReady) return;
  await db.batch([
    db.prepare('CREATE TABLE IF NOT EXISTS users (phone TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL, created INTEGER NOT NULL)'),
    db.prepare('CREATE INDEX IF NOT EXISTS users_token ON users (token_hash)'),
    db.prepare('CREATE TABLE IF NOT EXISTS codes (phone TEXT PRIMARY KEY, code TEXT NOT NULL, expires INTEGER NOT NULL, sent_at INTEGER NOT NULL, tries INTEGER NOT NULL)'),
    db.prepare('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, to_phone TEXT NOT NULL, from_phone TEXT NOT NULL, from_name TEXT NOT NULL, body TEXT NOT NULL, ts INTEGER NOT NULL)'),
    db.prepare('CREATE INDEX IF NOT EXISTS messages_to ON messages (to_phone, id)')
  ]);
  tablesReady = true;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
}
function randomCode() {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
}
const hasTwilio = env => !!(env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_VERIFY_SID);

async function twilio(env, path, params) {
  const r = await fetch('https://verify.twilio.com/v2/Services/' + env.TWILIO_VERIFY_SID + '/' + path, {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + btoa(env.TWILIO_ACCOUNT_SID + ':' + env.TWILIO_AUTH_TOKEN),
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams(params)
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, data };
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > MAX_BODY + 2000) return null;
  try { return JSON.parse(text) || {}; } catch (e) { return null; }
}
async function whoIs(request, db) {
  const h = request.headers.get('Authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  const hash = await sha256(h.slice(7));
  return await db.prepare('SELECT phone, name FROM users WHERE token_hash = ?').bind(hash).first();
}
const cleanName = v => String(v || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, 30);

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const db = env.DB;

    try {
      if (path === '/' || path === '/api/status') {
        if (!db) return fail(500, 'The database is not connected. Add a D1 binding named DB to this Worker.');
        await makeTables(db);
        return json({ ok: true, service: 'HELLO server', sms: hasTwilio(env) ? 'twilio' : 'test' });
      }
      if (!db) return fail(500, 'The database is not connected. Add a D1 binding named DB to this Worker.');
      await makeTables(db);
      const now = Date.now();

      /* ---- Step 1 of sign-in: send a code ---- */
      if (path === '/api/verify/start' && request.method === 'POST') {
        const b = await readBody(request);
        if (!b || !PHONE.test(b.phone || '')) return fail(400, 'That phone number does not look right. Include the area code.');
        const old = await db.prepare('SELECT sent_at FROM codes WHERE phone = ?').bind(b.phone).first();
        if (old && now - old.sent_at < 30000) return fail(429, 'A code was just sent. Wait 30 seconds and try again.');
        if (hasTwilio(env)) {
          const r = await twilio(env, 'Verifications', { To: b.phone, Channel: 'sms' });
          if (!r.ok) return fail(502, 'The text message could not be sent. ' + (r.data.message || ''));
          await db.prepare('INSERT OR REPLACE INTO codes (phone, code, expires, sent_at, tries) VALUES (?, ?, ?, ?, 0)')
            .bind(b.phone, '', now + 600000, now).run();
          return json({ ok: true, sms: 'twilio' });
        }
        const code = randomCode();
        await db.prepare('INSERT OR REPLACE INTO codes (phone, code, expires, sent_at, tries) VALUES (?, ?, ?, ?, 0)')
          .bind(b.phone, code, now + 600000, now).run();
        return json({ ok: true, sms: 'test', testCode: code });
      }

      /* ---- Step 2 of sign-in: check the code ---- */
      if (path === '/api/verify/check' && request.method === 'POST') {
        const b = await readBody(request);
        if (!b || !PHONE.test(b.phone || '')) return fail(400, 'That phone number does not look right.');
        const code = String(b.code || '').replace(/\D/g, '');
        const name = cleanName(b.name);
        if (!name) return fail(400, 'A name is needed.');
        if (code.length < 4 || code.length > 10) return fail(400, 'Type the code from the text message.');
        const row = await db.prepare('SELECT code, expires, tries FROM codes WHERE phone = ?').bind(b.phone).first();
        if (!row || row.expires < now) return fail(400, 'That code has expired. Ask for a new code.');
        if (row.tries >= 5) return fail(429, 'Too many wrong tries. Ask for a new code.');
        let good = false;
        if (hasTwilio(env)) {
          const r = await twilio(env, 'VerificationCheck', { To: b.phone, Code: code });
          good = r.ok && r.data.status === 'approved';
        } else {
          good = row.code !== '' && row.code === code;
        }
        if (!good) {
          await db.prepare('UPDATE codes SET tries = tries + 1 WHERE phone = ?').bind(b.phone).run();
          return fail(400, 'That code is not right.');
        }
        const token = randomHex(32);
        await db.batch([
          db.prepare('DELETE FROM codes WHERE phone = ?').bind(b.phone),
          db.prepare('INSERT INTO users (phone, name, token_hash, created) VALUES (?, ?, ?, ?) ON CONFLICT(phone) DO UPDATE SET name = excluded.name, token_hash = excluded.token_hash')
            .bind(b.phone, name, await sha256(token), now)
        ]);
        return json({ ok: true, token, phone: b.phone });
      }

      /* ---- Everything below needs a signed-in phone ---- */
      const me = await whoIs(request, db);
      if (!me) return fail(401, 'This phone is not signed in.');

      if (path === '/api/lookup' && request.method === 'GET') {
        const phone = url.searchParams.get('phone') || '';
        if (!PHONE.test(phone)) return fail(400, 'That phone number does not look right.');
        const u = await db.prepare('SELECT name FROM users WHERE phone = ?').bind(phone).first();
        return json({ found: !!u, name: u ? u.name : '' });
      }

      if (path === '/api/name' && request.method === 'POST') {
        const b = await readBody(request);
        const name = cleanName(b && b.name);
        if (!name) return fail(400, 'A name is needed.');
        await db.prepare('UPDATE users SET name = ? WHERE phone = ?').bind(name, me.phone).run();
        return json({ ok: true });
      }

      if (path === '/api/send' && request.method === 'POST') {
        const b = await readBody(request);
        if (!b) return fail(413, 'That message is too big to send.');
        if (!PHONE.test(b.to || '')) return fail(400, 'That phone number does not look right.');
        if (!b.body || typeof b.body !== 'object') return fail(400, 'The message is empty.');
        const body = JSON.stringify(b.body);
        if (body.length > MAX_BODY) return fail(413, 'That message is too big to send.');
        const to = await db.prepare('SELECT phone FROM users WHERE phone = ?').bind(b.to).first();
        if (!to) return fail(404, 'That number is not on HELLO yet.');
        const n = await db.prepare('SELECT COUNT(*) AS n FROM messages WHERE to_phone = ?').bind(b.to).first();
        if (n && n.n >= MAX_WAITING) return fail(429, 'That person has too many messages waiting.');
        await db.prepare('INSERT INTO messages (to_phone, from_phone, from_name, body, ts) VALUES (?, ?, ?, ?, ?)')
          .bind(b.to, me.phone, me.name, body, now).run();
        return json({ ok: true });
      }

      /* The phone calls this every few seconds.
         "ack" is the list of message ids the phone already has. Those are deleted here. */
      if (path === '/api/sync' && request.method === 'POST') {
        const b = (await readBody(request)) || {};
        const ack = (Array.isArray(b.ack) ? b.ack : []).filter(Number.isInteger).slice(0, 50);
        if (ack.length) {
          await db.prepare('DELETE FROM messages WHERE to_phone = ? AND id IN (' + ack.map(() => '?').join(',') + ')')
            .bind(me.phone, ...ack).run();
        }
        if (Math.random() < 0.02) {
          await db.prepare('DELETE FROM messages WHERE ts < ?').bind(now - KEEP_DAYS * 86400000).run();
          await db.prepare('DELETE FROM codes WHERE expires < ?').bind(now).run();
        }
        const rows = await db.prepare('SELECT id, from_phone, from_name, body, ts FROM messages WHERE to_phone = ? ORDER BY id LIMIT 5')
          .bind(me.phone).all();
        const messages = (rows.results || []).map(r => {
          let body = null;
          try { body = JSON.parse(r.body); } catch (e) {}
          return { id: r.id, from: r.from_phone, name: r.from_name, body, ts: r.ts };
        });
        return json({ messages });
      }

      return fail(404, 'Not found.');
    } catch (e) {
      return fail(500, 'Server error: ' + (e && e.message ? e.message : 'unknown'));
    }
  }
};
