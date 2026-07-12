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

let GAME = { meta: {}, starters: {} };
try { GAME = JSON.parse(fs.readFileSync(path.join(__dirname, 'gamedata.json'), 'utf8')); } catch { console.error('gamedata.json missing — economy endpoints disabled'); }
const finishedRooms = new Map(); // code -> {users:[names], t, claimed:{}}

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
  // --------- SERVER-AUTHORITATIVE collections & economy.
  // Clients can only ask the server to perform actions; they can never write
  // their collection directly, so editing the game files grants nothing.
  if (msg.t && msg.t.startsWith('svr')) {
    const u = findUser(msg.username);
    if (!u || !msg.token || u.token !== msg.token) return reply({ t: 'coll', ok: false, why: 'Not logged in — log in again.' });
    const c = (u.collection = u.collection || { owned: {}, berries: 0 });
    const ok = (extra = {}) => { saveUsers(); reply({ t: 'coll', ok: true, data: u.collection, ...extra }); };
    const fail = (why) => reply({ t: 'coll', ok: false, why, data: u.collection });
    const today = new Date().toISOString().slice(0, 10);

    if (msg.t === 'svrColl') return ok();

    if (msg.t === 'svrStarter') {
      if (c.starter) return fail('Starter already chosen.');
      const deck = GAME.starters[msg.leader];
      if (!deck) return fail('Unknown starter leader.');
      c.starter = msg.leader;
      c.berries = (c.berries || 0) + 200;
      for (const code of [msg.leader, ...deck]) c.owned[code] = (c.owned[code] || 0) + 1;
      return ok();
    }

    if (msg.t === 'svrOpenPack') {
      const setId = String(msg.setId || '');
      const pool = Object.entries(GAME.meta).filter(([, m]) => m[0] === setId);
      if (!pool.length) return fail('Unknown set.');
      if (c.lastDaily !== today) { c.lastDaily = today; c.openedToday = 0; }
      if (msg.paid) {
        if ((c.berries || 0) < 100) return fail('Not enough Berries.');
        c.berries -= 100;
      } else {
        if ((c.openedToday || 0) >= 3) return fail('No free packs left today.');
        c.openedToday = (c.openedToday || 0) + 1;
      }
      const byR = {};
      for (const [code, m] of pool) (byR[m[1]] = byR[m[1]] || []).push(code);
      const pick = (rs) => { for (const r of rs) { const p = byR[r]; if (p && p.length) return p[Math.floor(Math.random() * p.length)]; } return pool[Math.floor(Math.random() * pool.length)][0]; };
      const cards = [];
      for (let i = 0; i < 7; i++) cards.push(pick(['C', 'UC']));
      for (let i = 0; i < 3; i++) cards.push(pick(['UC', 'C']));
      cards.push(pick(['R', 'UC']));
      const roll = Math.random();
      if ((c.pity || 0) >= 9) cards.push(pick(['SR', 'L', 'SEC', 'R']));
      else if (roll < 0.08) cards.push(pick(['SEC', 'SR', 'L', 'R']));
      else if (roll < 0.23) cards.push(pick(['L', 'SR', 'R']));
      else if (roll < 0.55) cards.push(pick(['SR', 'R']));
      else cards.push(pick(['R', 'UC']));
      const HIT = new Set(['SR', 'L', 'SEC', 'TR']);
      const hits = cards.filter((code) => HIT.has(GAME.meta[code][1]));
      c.pity = hits.length ? 0 : (c.pity || 0) + 1;
      const newOnes = [];
      for (const code of cards) {
        if (!c.owned[code]) newOnes.push(code);
        c.owned[code] = (c.owned[code] || 0) + 1;
      }
      return ok({ cards, newOnes, hits });
    }

    const SELL = { C: 3, UC: 6, R: 15, SR: 40, L: 60, SEC: 100, TR: 40 };
    const priceOf = (code) => SELL[(GAME.meta[code] || [])[1]] || 3;

    if (msg.t === 'svrSell') {
      const code = String(msg.code || '');
      const own = c.owned[code] || 0;
      const k = Math.min(Math.max(0, (msg.n | 0) || 1), Math.max(0, own - 1));
      if (k <= 0) return fail('Nothing to sell (you always keep 1 copy).');
      c.owned[code] = own - k;
      const earned = k * priceOf(code);
      c.berries = (c.berries || 0) + earned;
      return ok({ earned });
    }

    if (msg.t === 'svrSellExtras') {
      let earned = 0;
      for (const [code, own] of Object.entries(c.owned)) {
        if (own > 4) { earned += (own - 4) * priceOf(code); c.owned[code] = 4; }
      }
      c.berries = (c.berries || 0) + earned;
      return ok({ earned });
    }

    if (msg.t === 'svrClaimBot') {
      // small, capped practice reward — the server can't verify bot games
      if (c.botDay !== today) { c.botDay = today; c.botClaims = 0; }
      if ((c.botClaims || 0) >= 5) return fail('Daily practice rewards used up.');
      c.botClaims = (c.botClaims || 0) + 1;
      const amt = msg.won ? 50 : 25;
      c.berries = (c.berries || 0) + amt;
      return ok({ earned: amt });
    }

    if (msg.t === 'svrClaimMatch') {
      const code = String(msg.room || '').toUpperCase();
      let room = finishedRooms.get(code);
      if (!room) {
        const live = rooms.get(code);
        if (live && live.users[0] && live.users[1] && Date.now() - live.created >= 180000) {
          live.claimGuard = live.claimGuard || { users: live.users.filter(Boolean), claimed: {} };
          room = live.claimGuard;
        }
      }
      const uname = Object.keys(users).find((k) => users[k] === u);
      if (!room || !room.users.includes(uname)) return fail('No completed match found for you in that room.');
      if (room.claimed[uname]) return fail('Reward already claimed.');
      room.claimed[uname] = true;
      const amt = msg.won ? 100 : 50;
      c.berries = (c.berries || 0) + amt;
      return ok({ earned: amt });
    }
    return fail('Unknown request.');
  }
  // legacy client-pushed collections are no longer accepted
  if (msg.t === 'collSave') return reply({ t: 'coll', ok: false, why: 'Collections are managed by the server now.' });
  if (msg.t === 'collGet') {
    const u = findUser(msg.username);
    if (!u || !msg.token || u.token !== msg.token) return reply({ t: 'coll', ok: false, why: 'Not logged in.' });
    return reply({ t: 'coll', ok: true, data: u.collection || null });
  }
  // deck-ownership check used by hosts before starting a match
  if (msg.t === 'verifyDeck') {
    const u = findUser(msg.username);
    if (!u || !u.collection) return reply({ t: 'deckCheck', ok: false, why: 'Unknown player or no collection.' });
    const owned = u.collection.owned || {};
    const counts = {};
    for (const code of msg.deck || []) counts[code] = (counts[code] || 0) + 1;
    counts[msg.leader] = (counts[msg.leader] || 0) + 1;
    for (const [code, n] of Object.entries(counts)) {
      if ((owned[code] || 0) < n) return reply({ t: 'deckCheck', ok: false, why: `They don't own ${n}x ${code}.` });
    }
    return reply({ t: 'deckCheck', ok: true });
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

    if (msg && (['register', 'login', 'recoverRequest', 'recoverConfirm', 'collGet', 'collSave', 'verifyDeck'].includes(msg.t) || String(msg.t).startsWith('svr'))) {
      handleAccountMsg(ws, msg);
      return;
    }
    if (msg && msg.t === 'create') {
      const code = newCode();
      ws.room = code; ws.isHost = true;
      rooms.set(code, { host: ws, guest: null, created: Date.now(), users: [normName(msg.username) || null, null] });
      send(ws, { t: 'room', code });
      return;
    }
    if (msg && msg.t === 'joinRoom') {
      const room = rooms.get(String(msg.code || '').toUpperCase().trim());
      if (!room || !room.host || room.host.readyState !== 1) { send(ws, { t: 'roomError', why: 'No such room — check the code with the host.' }); return; }
      if (room.guest) { send(ws, { t: 'roomError', why: 'That room is already full.' }); return; }
      room.guest = ws;
      ws.room = room.host.room; ws.isHost = false;
      room.users[1] = normName(msg.username) || null;
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
    if (ws.isHost) {
      // record real matches (two named players, lasted ≥3 minutes) for rewards
      if (room.users[0] && room.users[1] && Date.now() - room.created >= 180000) {
        finishedRooms.set(ws.room, { users: room.users.filter(Boolean), t: Date.now(), claimed: {} });
        if (finishedRooms.size > 300) finishedRooms.delete(finishedRooms.keys().next().value);
      }
      rooms.delete(ws.room);
    } else room.guest = null;
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
