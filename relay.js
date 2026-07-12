// ============================================================================
// Tiny room-code relay for One Piece TCG.
//
// Players connect here instead of to each other, so nobody needs IP addresses
// or port forwarding: the host gets a 4-letter room code, the friend types it.
// The relay never understands the game — it just pipes messages between the
// two sockets of a room. Hidden information stays on the host as always.
//
// Run it anywhere with Node.js ≥ 18:
//     npm install ws && node relay.js          (default port 7460, or $PORT)
// Free hosting: create a free "Web Service" on render.com / railway.app from
// a repo containing just this file + `{"dependencies":{"ws":"^8"}}`, start
// command `node relay.js`. Then use wss://your-app.onrender.com in the game.
// ============================================================================
'use strict';

const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');

const PORT = process.env.PORT || 7460;
const wss = new WebSocketServer({ port: PORT });
const rooms = new Map(); // code -> { host, guest }

// ------------------------------------------------------------------ accounts
// Username/password accounts with optional email recovery. Passwords are
// scrypt-hashed. Recovery emails are sent through Resend (resend.com, free
// tier) when RESEND_API_KEY and EMAIL_FROM env vars are set on the server.
const USERS_FILE = process.env.USERS_FILE || path.join(__dirname, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch {}
const saveUsers = () => { try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 1)); } catch (e) { console.error('users save failed:', e.message); } };
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 32).toString('hex');
const normName = (u) => String(u || '').trim();
const findUser = (u) => users[Object.keys(users).find((k) => k.toLowerCase() === normName(u).toLowerCase())];

function sendEmail(to, subject, text, cb) {
  if (!process.env.RESEND_API_KEY || !process.env.EMAIL_FROM) { cb(new Error('not configured')); return; }
  const body = JSON.stringify({ from: process.env.EMAIL_FROM, to: [to], subject, text });
  const req = https.request({
    hostname: 'api.resend.com', path: '/emails', method: 'POST',
    headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  }, (res) => cb(res.statusCode >= 200 && res.statusCode < 300 ? null : new Error(`mail API ${res.statusCode}`)));
  req.on('error', cb);
  req.end(body);
}

function handleAccountMsg(ws, msg) {
  const reply = (obj) => send(ws, obj);
  if (msg.t === 'register') {
    const uname = normName(msg.username);
    const email = String(msg.email || '').trim().toLowerCase();
    if (!/^[A-Za-z0-9_.-]{3,20}$/.test(uname)) return reply({ t: 'auth', ok: false, why: 'Username must be 3–20 letters/numbers (also _ . -).' });
    if (String(msg.password || '').length < 6) return reply({ t: 'auth', ok: false, why: 'Password must be at least 6 characters.' });
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return reply({ t: 'auth', ok: false, why: 'Enter a valid email address.' });
    if (findUser(uname)) return reply({ t: 'auth', ok: false, why: 'That username is taken.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const token = crypto.randomBytes(24).toString('hex');
    users[uname] = { email, salt, hash: hashPw(msg.password, salt), token, created: Date.now() };
    saveUsers();
    return reply({ t: 'auth', ok: true, username: uname, token });
  }
  if (msg.t === 'login') {
    const u = findUser(msg.username);
    if (!u || hashPw(msg.password, u.salt) !== u.hash) return reply({ t: 'auth', ok: false, why: 'Wrong username or password.' });
    const uname = Object.keys(users).find((k) => users[k] === u);
    u.token = u.token || crypto.randomBytes(24).toString('hex');
    saveUsers();
    return reply({ t: 'auth', ok: true, username: uname, token: u.token });
  }
  if (msg.t === 'recoverRequest') {
    const email = String(msg.email || '').trim().toLowerCase();
    const uname = Object.keys(users).find((k) => users[k].email === email);
    if (!uname) return reply({ t: 'recover', ok: false, why: 'No account uses that email.' });
    const code = String(crypto.randomInt(100000, 999999));
    users[uname].resetCode = code;
    users[uname].resetExp = Date.now() + 15 * 60 * 1000;
    saveUsers();
    sendEmail(email, 'One Piece TCG — account recovery',
      `Ahoy!\n\nYour username is: ${uname}\nYour password reset code is: ${code}\n\nThe code expires in 15 minutes. If you didn't request this, ignore this email.`,
      (err) => {
        if (err) reply({ t: 'recover', ok: false, why: err.message === 'not configured' ? 'This server has no email service configured — ask the server owner.' : 'Could not send the email — try again later.' });
        else reply({ t: 'recover', ok: true, sent: true });
      });
    return;
  }
  if (msg.t === 'recoverConfirm') {
    const email = String(msg.email || '').trim().toLowerCase();
    const uname = Object.keys(users).find((k) => users[k].email === email);
    const u = uname && users[uname];
    if (!u || !u.resetCode || u.resetCode !== String(msg.code || '') || Date.now() > u.resetExp) {
      return reply({ t: 'recover', ok: false, why: 'Wrong or expired code.' });
    }
    if (String(msg.newPassword || '').length < 6) return reply({ t: 'recover', ok: false, why: 'New password must be at least 6 characters.' });
    u.salt = crypto.randomBytes(16).toString('hex');
    u.hash = hashPw(msg.newPassword, u.salt);
    u.token = crypto.randomBytes(24).toString('hex');
    delete u.resetCode; delete u.resetExp;
    saveUsers();
    return reply({ t: 'recover', ok: true, username: uname, token: u.token });
  }
  // --------- server-synced collections (requires a valid login token)
  if (msg.t === 'collGet' || msg.t === 'collSave') {
    const u = findUser(msg.username);
    if (!u || !msg.token || u.token !== msg.token) return reply({ t: 'coll', ok: false, why: 'Not logged in — log in again.' });
    if (msg.t === 'collGet') return reply({ t: 'coll', ok: true, data: u.collection || null });
    const raw = JSON.stringify(msg.data || {});
    if (raw.length > 400000) return reply({ t: 'coll', ok: false, why: 'Collection too large.' });
    u.collection = msg.data;
    saveUsers();
    return reply({ t: 'coll', ok: true });
  }
}

const CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no ambiguous chars
function newCode() {
  for (;;) {
    let c = '';
    for (let i = 0; i < 4; i++) c += CODE_CHARS[Math.floor(Math.random() * CODE_CHARS.length)];
    if (!rooms.has(c)) return c;
  }
}
const send = (ws, obj) => { try { ws.send(JSON.stringify(obj)); } catch {} };

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (data, isBinary) => {
    // control messages
    let msg = null;
    if (!isBinary) { try { msg = JSON.parse(data.toString()); } catch {} }

    if (msg && ['register', 'login', 'recoverRequest', 'recoverConfirm', 'collGet', 'collSave'].includes(msg.t)) {
      handleAccountMsg(ws, msg);
      return;
    }
    if (msg && msg.t === 'create') {
      const code = newCode();
      ws.room = code; ws.isHost = true;
      rooms.set(code, { host: ws, guest: null });
      send(ws, { t: 'room', code });
      return;
    }
    if (msg && msg.t === 'joinRoom') {
      const room = rooms.get(String(msg.code || '').toUpperCase().trim());
      if (!room || !room.host || room.host.readyState !== 1) { send(ws, { t: 'roomError', why: 'No such room — check the code with the host.' }); return; }
      if (room.guest) { send(ws, { t: 'roomError', why: 'That room is already full.' }); return; }
      room.guest = ws;
      ws.room = room.host.room; ws.isHost = false;
      send(room.host, { t: 'paired' });
      send(ws, { t: 'paired' });
      return;
    }

    // anything else: pipe to the partner
    const room = rooms.get(ws.room);
    if (!room) return;
    const partner = ws.isHost ? room.guest : room.host;
    if (partner && partner.readyState === 1) partner.send(data, { binary: isBinary });
  });

  ws.on('close', () => {
    const room = rooms.get(ws.room);
    if (!room) return;
    const partner = ws.isHost ? room.guest : room.host;
    if (partner && partner.readyState === 1) send(partner, { t: 'peerLeft' });
    if (ws.isHost) rooms.delete(ws.room);
    else room.guest = null;
  });
  ws.on('error', () => {});
});

// keepalive (free hosts kill idle connections)
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);

console.log(`One Piece TCG relay listening on port ${PORT}`);
