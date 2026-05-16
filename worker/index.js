// ============================================================
// ChronQuest API Worker
// Handles: register, confirm-email, login, logout,
//          device registration, session auth
// ============================================================

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ success: false, error: msg }, status);
}

// ── Crypto helpers ────────────────────────────────────────────
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt    = crypto.getRandomValues(new Uint8Array(16));
  const keyMat  = await crypto.subtle.importKey('raw', encoder.encode(password),
    { name: 'PBKDF2' }, false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2,'0')).join('');
  const hashHex = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2,'0')).join('');
  return `${saltHex}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt    = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const encoder = new TextEncoder();
  const keyMat  = await crypto.subtle.importKey('raw', encoder.encode(password),
    { name: 'PBKDF2' }, false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMat, 256);
  const check   = Array.from(new Uint8Array(derived)).map(b => b.toString(16).padStart(2,'0')).join('');
  return check === hashHex;
}

function randomToken(bytes = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map(b => b.toString(16).padStart(2,'0')).join('');
}

function randomId() { return randomToken(16); }

// ── Email via Resend ──────────────────────────────────────────
async function sendConfirmationEmail(env, email, token) {
  const confirmUrl = `https://chronquest.com/confirm?token=${token}`;
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      from:    'ChronQuest <noreply@chronquest.com>',
      to:      [email],
      subject: 'Confirm your ChronQuest account',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem">
          <h2 style="color:#c9a84c">ChronQuest</h2>
          <p>Thanks for signing up! Click below to confirm your email address.</p>
          <a href="${confirmUrl}"
             style="display:inline-block;margin:1.5rem 0;padding:0.75rem 1.5rem;
                    background:#c9a84c;color:#0a0800;border-radius:6px;
                    font-weight:bold;text-decoration:none">
            Confirm Email
          </a>
          <p style="color:#888;font-size:0.85rem">
            Or paste this link into your browser:<br>${confirmUrl}
          </p>
          <p style="color:#888;font-size:0.85rem">
            If you didn't sign up for ChronQuest, you can safely ignore this email.
          </p>
        </div>`,
    }),
  });
  return res.ok;
}

// ── Session auth middleware ────────────────────────────────────
async function getSession(env, request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    'SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?'
  ).bind(token, now).first();
  return row ? row.user_id : null;
}

// ── Route handlers ────────────────────────────────────────────

// POST /api/register
async function handleRegister(env, body) {
  const { email, password } = body;
  if (!email || !password) return err('Email and password required');
  if (password.length < 8)  return err('Password must be at least 8 characters');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (existing) return err('An account with this email already exists');

  const id                = randomId();
  const password_hash     = await hashPassword(password);
  const confirmation_token = randomToken();

  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, confirmation_token) VALUES (?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), password_hash, confirmation_token).run();

  await sendConfirmationEmail(env, email, confirmation_token);

  return json({ success: true, message: 'Check your email to confirm your account.' });
}

// GET /api/confirm?token=...
async function handleConfirm(env, token) {
  if (!token) return err('Missing token');
  const user = await env.DB.prepare(
    'SELECT id FROM users WHERE confirmation_token = ? AND confirmed = 0'
  ).bind(token).first();
  if (!user) return err('Invalid or already used confirmation link', 404);

  await env.DB.prepare(
    'UPDATE users SET confirmed = 1, confirmation_token = NULL WHERE id = ?'
  ).bind(user.id).run();

  return json({ success: true, message: 'Email confirmed. You can now log in.' });
}

// POST /api/login
async function handleLogin(env, body) {
  const { email, password } = body;
  if (!email || !password) return err('Email and password required');

  const user = await env.DB.prepare(
    'SELECT id, password_hash, confirmed FROM users WHERE email = ?'
  ).bind(email.toLowerCase()).first();

  if (!user) return err('Invalid email or password', 401);
  if (!user.confirmed) return err('Please confirm your email before logging in', 401);

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) return err('Invalid email or password', 401);

  const token     = randomToken();
  const expiresAt = Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60); // 30 days

  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(token, user.id, expiresAt).run();

  return json({ success: true, token, expires_at: expiresAt });
}

// POST /api/logout
async function handleLogout(env, request) {
  const auth  = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return json({ success: true });
}

// GET /api/me
async function handleMe(env, request) {
  const userId = await getSession(env, request);
  if (!userId) return err('Not authenticated', 401);

  const user = await env.DB.prepare(
    'SELECT id, email, created_at FROM users WHERE id = ?'
  ).bind(userId).first();

  const devices = await env.DB.prepare(
    'SELECT id, mac_address, nickname, created_at FROM devices WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(userId).all();

  return json({ success: true, user, devices: devices.results });
}

// POST /api/devices
async function handleAddDevice(env, request, body) {
  const userId = await getSession(env, request);
  if (!userId) return err('Not authenticated', 401);

  const { mac_address, nickname } = body;
  if (!mac_address) return err('Device ID required');

  const mac = mac_address.toUpperCase().trim();
  if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(mac)) return err('Invalid Device ID format');

  // Check if MAC already registered to this user
  const existing = await env.DB.prepare(
    'SELECT id FROM devices WHERE mac_address = ? AND user_id = ?'
  ).bind(mac, userId).first();
  if (existing) return err('This device is already registered to your account');

  // Check if MAC registered to another user
  const taken = await env.DB.prepare(
    'SELECT id FROM devices WHERE mac_address = ?'
  ).bind(mac).first();
  if (taken) return err('This device is already registered to another account');

  const id = randomId();
  await env.DB.prepare(
    'INSERT INTO devices (id, user_id, mac_address, nickname) VALUES (?, ?, ?, ?)'
  ).bind(id, userId, mac, nickname || null).run();

  return json({ success: true, device: { id, mac_address: mac, nickname: nickname || null } });
}

// DELETE /api/devices/:mac
async function handleRemoveDevice(env, request, mac) {
  const userId = await getSession(env, request);
  if (!userId) return err('Not authenticated', 401);

  const device = await env.DB.prepare(
    'SELECT id FROM devices WHERE mac_address = ? AND user_id = ?'
  ).bind(mac.toUpperCase(), userId).first();
  if (!device) return err('Device not found', 404);

  await env.DB.prepare('DELETE FROM devices WHERE id = ?').bind(device.id).run();
  return json({ success: true });
}

// ── Main router ───────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    let body = {};
    if (method === 'POST' && request.headers.get('Content-Type')?.includes('application/json')) {
      try { body = await request.json(); } catch {}
    }

    if (path === '/api/register'      && method === 'POST') return handleRegister(env, body);
    if (path === '/api/confirm'       && method === 'GET')  return handleConfirm(env, url.searchParams.get('token'));
    if (path === '/api/login'         && method === 'POST') return handleLogin(env, body);
    if (path === '/api/logout'        && method === 'POST') return handleLogout(env, request);
    if (path === '/api/me'            && method === 'GET')  return handleMe(env, request);
    if (path === '/api/devices'       && method === 'POST') return handleAddDevice(env, request, body);
    if (path.startsWith('/api/devices/') && method === 'DELETE') {
      return handleRemoveDevice(env, request, path.split('/').pop());
    }

    if (path === '/api/health') return json({ success: true, status: 'ok' });

    return err('Not found', 404);
  },
};
