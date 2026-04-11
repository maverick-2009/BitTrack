/**
 * BitTrack Panel — Express web server for the panel UI
 */

'use strict';

// ─── TIMESTAMPED LOG ─────────────────────────────────────────────────────────
// Uses the original console (no patch) and manually prepends [PANEL].
function nowStr() {
  const tz  = readJSON(FILES.config, {})?.general?.timezone || 'UTC';
  const fmt = new Intl.DateTimeFormat([], {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
  const parts = Object.fromEntries(
    fmt.formatToParts(new Date()).filter(p => p.type !== 'literal').map(p => [p.type, p.value])
  );
  return `[${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}]`;
}
const _out = console._log   || console.log;
const _err = console._error || console.error;
const _wrn = console._warn  || console.warn;
const _log = {
  info:  (...a) => _out(`${nowStr()} [PANEL]   ✅ `, ...a),
  warn:  (...a) => _wrn(`${nowStr()} [PANEL]   ⚠️ `, ...a),
  error: (...a) => _err(`${nowStr()} [PANEL]   ❌ `, ...a),
};


const http   = require('http');
const https  = require('https');
const net    = require('net');
const tls    = require('tls');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { analyzeDescriptor } = require('./descriptor-parser');

const dataDir    = path.join(__dirname, 'data');
function getPanelPort() {
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(dataDir, 'config.json'), 'utf8'));
    return cfg?.general?.panelPort || 8585;
  } catch { return 8585; }
}
const PANEL_PORT = getPanelPort();

fs.mkdirSync(dataDir, { recursive: true });

const FILES = {
  config:       path.join(dataDir, 'config.json'),
  wallets:      path.join(dataDir, 'wallets.json'),
  servers:      path.join(dataDir, 'servers.json'),
  state:        path.join(dataDir, 'state.json'),
  auth:         path.join(dataDir, 'panel-auth.json'),
  runtime:      path.join(dataDir, 'runtime.json'),
  priceHistory: path.join(dataDir, 'historicalprice.json'),
  txHistory:    path.join(dataDir, 'txhistory.json'),
};

// ─── DEFAULT SERVERS ──────────────────────────────────────────────────────────
// Created on first run if servers.json does not exist.
const DEFAULT_SERVERS = [
  { name: 'umbrel.local',       host: 'umbrel.local',                 port: 50001, tls: false, builtin: false },
  { name: 'umbrel (Fulcrum)',   host: 'umbrel.local',                 port: 50002, tls: false, builtin: false },
  { name: 'Emzy.de',            host: 'electrum.emzy.de',             port: 50002, tls: true,  builtin: false },
  { name: 'Blockstream',        host: 'blockstream.info',             port: 700,   tls: true,  builtin: false },
  { name: 'Bitcoin.lu.ke',      host: 'bitcoin.lu.ke',                port: 50002, tls: true,  builtin: false },
];

function ensureServers() {
  if (!fs.existsSync(FILES.servers)) {
    writeJSON(FILES.servers, DEFAULT_SERVERS);
    _log.info('servers.json created with default servers');
  }
}

// ─── SESSION & RATE LIMITING ──────────────────────────────────────────────────
const SESSION_TTL_MS   = 24 * 60 * 60 * 1000; // 24 hours
const LOGIN_MAX_TRIES  = 5;                     // max failed attempts before block
const LOGIN_BLOCK_MS   = 15 * 60 * 1000;        // block duration: 15 minutes
const LOGIN_WINDOW_MS  = 10 * 60 * 1000;        // sliding window to count attempts

// In-memory sessions: token → { created }
const sessions = new Map();

// In-memory login attempts: ip → { attempts, windowStart, blockedUntil }
const loginAttempts = new Map();

// Purge expired sessions periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) {
    if (now - s.created > SESSION_TTL_MS) sessions.delete(token);
  }
}, 60 * 60 * 1000); // run every hour

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function isRateLimited(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || !entry.blockedUntil) return false;
  if (Date.now() < entry.blockedUntil) return true;
  // Block expired — clean up
  loginAttempts.delete(ip);
  return false;
}

function recordFailedLogin(ip) {
  const now = Date.now();
  let entry = loginAttempts.get(ip);
  if (!entry) {
    entry = { attempts: 0, windowStart: now, blockedUntil: null };
  }
  // Reset window if expired
  if (now - entry.windowStart > LOGIN_WINDOW_MS) {
    entry.attempts = 0;
    entry.windowStart = now;
    entry.blockedUntil = null;
  }
  entry.attempts++;
  if (entry.attempts >= LOGIN_MAX_TRIES) {
    entry.blockedUntil = now + LOGIN_BLOCK_MS;
    _log.warn(`[auth] IP ${ip} blocked for ${LOGIN_BLOCK_MS / 60000} min after ${entry.attempts} failed attempts`);
  }
  loginAttempts.set(ip, entry);
}

function recordSuccessfulLogin(ip) {
  loginAttempts.delete(ip);
}

// ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'BitTrack_salt').digest('hex');
}

function getAuth() {
  try { return JSON.parse(fs.readFileSync(FILES.auth, 'utf8')); }
  catch { return { hash: hashPassword('admin') }; } // default password
}

function saveAuth(data) {
  fs.writeFileSync(FILES.auth, JSON.stringify(data, null, 2));
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function checkToken(req) {
  const token = req.headers['x-auth-token'] || '';
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() - session.created > SESSION_TTL_MS) {
    sessions.delete(token); // expired — remove
    return false;
  }
  return true;
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function readJSON(file, fallback = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

ensureServers();

function bodyJSON(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function json(res, data, status = 200) {
  const payload = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function unauthorized(res) {
  json(res, { error: 'unauthorized' }, 401);
}

// ─── TEST ELECTRUM ─────────────────────────────────────────────────────────────
function testElectrum(host, port, useTLS) {
  return new Promise(resolve => {
    const timeout = setTimeout(() => { sock?.destroy(); resolve({ ok: false, error: 'timeout' }); }, 8000);
    const opts = { host, port, rejectUnauthorized: false };
    let sock;
    const onConnect = () => {
      sock.write(JSON.stringify({ id: 1, method: 'server.version', params: ['BitTrack-Panel', '1.4'] }) + '\n');
    };
    sock = useTLS ? tls.connect(opts, onConnect) : net.connect({ host, port }, onConnect);
    sock.setEncoding('utf8');
    let buf = '';
    sock.on('data', d => {
      buf += d;
      if (buf.includes('\n')) {
        try {
          const msg = JSON.parse(buf.trim().split('\n')[0]);
          clearTimeout(timeout); sock.destroy();
          const ver = msg.result ? (Array.isArray(msg.result) ? msg.result.join(' / ') : msg.result) : 'OK';
          resolve({ ok: true, version: ver });
        } catch { clearTimeout(timeout); sock.destroy(); resolve({ ok: false, error: 'invalid response' }); }
      }
    });
    sock.on('error', e => { clearTimeout(timeout); resolve({ ok: false, error: e.message }); });
    if (!useTLS) sock.on('connect', onConnect);
  });
}

// ─── TEST TELEGRAM ─────────────────────────────────────────────────────────────
function testTelegram(token, chatId) {
  return new Promise(resolve => {
    const text = '🔔 BitTrack Panel — connection test OK';
    const body = JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' });
    const req  = https.request({
      hostname: 'api.telegram.org', path: `/bot${token}/sendMessage`,
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { const r = JSON.parse(d); r.ok ? resolve({ ok: true }) : resolve({ ok: false, error: r.description }); }
        catch { resolve({ ok: false, error: 'invalid response' }); }
      });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.write(body); req.end();
  });
}

// ─── TEST NTFY ────────────────────────────────────────────────────────────────
function testNtfy(url, token) {
  return new Promise(resolve => {
    if (!url) return resolve({ ok: false, error: 'URL not provided' });
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, error: 'invalid URL' }); }
    const text    = '🔔 BitTrack — connection test OK';
    const body    = Buffer.from(text, 'utf8');
    const headers = {
      'Content-Type':   'text/plain',
      'Content-Length': body.length,
      'Markdown':       'yes',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const req = lib.request({
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname,
      method:   'POST',
      headers,
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        res.statusCode >= 200 && res.statusCode < 300
          ? resolve({ ok: true })
          : resolve({ ok: false, error: `HTTP ${res.statusCode}: ${d.trim()}` });
      });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.write(body); req.end();
  });
}
function isBitcoinAddress(str) {
  str = str.trim();
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(str)) return true;
  if (/^bc1[ac-hj-np-z02-9]{11,71}$/.test(str)) return true;
  if (/^tb1[ac-hj-np-z02-9]{11,71}$/.test(str)) return true;
  if (/^(bc1p|tb1p)[ac-hj-np-z02-9]{8,87}$/.test(str)) return true;
  return false;
}

// Adds /<0;1>/* after pub keys that do not yet have a derivPath,
// Ensure separating comma between adjacent keys and add /<0;1>/*
function addDerivPaths(str) {
  let r = str
    // Step 1: remove space between ] and next key: "] Zpub" → "]Zpub"
    .replace(/(\])\s+(?=[xyYzZuUvVtT]pub)/g, ']')
    // Step 2: space between end of key and start of next ([fp] or key) → ','
    .replace(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)\s+(?=\[|[xyYzZuUvVtT]pub)/g, '$1,')
    // Step 3: space between existing derivPath and next key → ','
    .replace(/(\/\*)\s+(?=\[|[xyYzZuUvVtT]pub)/g, '$1,')
    // Step 4: ensure comma between /<0;1>/* and [ when no separator
    .replace(/(\/\*)(?=\[)/g, '$1,');
  // Step 5: add /<0;1>/* where no path exists yet
  r = r.replace(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)(?!\/)/g, m => m + '/<0;1>/*');
  return r;
}

// Script type from key prefix (ypub/zpub/Ypub/Zpub have defined semantics)
// isMultisig: ypub in multisig → P2SH-WSH (Ypub-equivalent); zpub in multisig → P2WSH
function detectKeyType(key, isMultisig) {
  if (/^ypub|^upub/.test(key)) return isMultisig ? 'P2SH-WSH' : 'P2SH-WPKH';
  if (/^zpub|^vpub/.test(key)) return isMultisig ? 'P2WSH'    : 'P2WPKH';
  if (/^Ypub|^Upub/.test(key)) return 'P2SH-WSH';
  if (/^Zpub|^Vpub/.test(key)) return 'P2WSH';
  return null; // xpub/tpub — inferred from derivation path
}

// Script type from derivation path (BIP44/49/84/86/48)
function inferFromPath(str) {
  if (/86h|86[']/.test(str)) return 'P2TR';
  if (/84h|84[']/.test(str)) return 'P2WPKH';
  if (/49h|49[']/.test(str)) return 'P2SH-WPKH';
  if (/48h|48[']/.test(str)) return 'P2WSH';
  if (/44h|44[']/.test(str)) return 'P2PKH';
  // xpub with no BIP path → Legacy P2PKH (xpub is the original pre-BIP84 format)
  return 'P2PKH';
}

// Fix missing commas between keys inside an already-wrapped descriptor
// e.g. xpub.../<0;1>/*[fp]xpub → xpub.../<0;1>/*,[fp]xpub
function fixMissingCommas(str) {
  return str
    .replace(/(\/\*)\s*(?=\[)/g,  '$1,')   // /*[  →  /*,[
    .replace(/(\/\*)\s*(?=[xyYzZuUvVtT]pub)/g, '$1,'); // /* zpub → /*,zpub
}

function normalizeDescriptor(desc) {
  // Normalize whitespace (newlines/tabs → single space)
  const clean = desc.trim().split('#')[0].trim()
    .replace(/[\r\n\t]+/g, ' ')   // newlines → space
    .replace(/\s{2,}/g, ' ')        // multiple spaces → one
    .replace(/\]\s+([xyYzZuUvVtT])/g, ']$1')  // remove space between ] and key
    .replace(/\[\s+/g, '[');        // remove space after [

  // 1. Plain address → addr()
  if (isBitcoinAddress(clean)) return `addr(${clean})`;

  // 2. Already has complete wrapper
  const hasWrapper   = /^(tr|wpkh|pkh|sh|wsh|addr|combo)\(/.test(clean);
  const hasDerivPath = /<\d+;\d+>\/\*/.test(clean) || /\/\d+\/\*/.test(clean);
  if (hasWrapper && hasDerivPath)  return fixMissingCommas(clean); // case 4: complete
  if (hasWrapper && !hasDerivPath) return addDerivPaths(clean);   // case 3: missing path

  // 3. No wrapper — detect type and build the full descriptor
  const keys       = [...clean.matchAll(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)/g)].map(m => m[1]);
  if (!keys.length) return clean; // unrecognized — return cleaned input

  const isMultisig = keys.length > 1;
  const keyType    = detectKeyType(keys[0], isMultisig);
  const scriptType = keyType || inferFromPath(clean);
  const withPaths  = addDerivPaths(clean);

  if (isMultisig) {
    // Extract M from start: "2 [fp]Xpub..." or "2,[fp]Xpub..."
    const mMatch = clean.match(/^\s*(\d+)\s*[,\s]/);
    const m = mMatch ? parseInt(mMatch[1]) : 1;
    switch (scriptType) {
      case 'P2WSH':    return `wsh(sortedmulti(${m},${withPaths}))`;
      case 'P2SH-WSH': return `sh(wsh(sortedmulti(${m},${withPaths})))`;
      default:         return `wsh(sortedmulti(${m},${withPaths}))`;
    }
  }

  switch (scriptType) {
    case 'P2PKH':     return `pkh(${withPaths})`;
    case 'P2SH-WPKH': return `sh(wpkh(${withPaths}))`;
    case 'P2WPKH':   return `wpkh(${withPaths})`;
    case 'P2TR':      return `tr(${withPaths})`;
    // Standalone Ypub/Upub are P2SH-WSH — wrap with sh(wsh(...))
    case 'P2SH-WSH':  return `sh(wsh(${withPaths}))`;
    case 'P2WSH':     return `wsh(${withPaths})`;
    default:          return `pkh(${withPaths})`; // fallback: unknown xpub → legacy
  }
}

// ─── DEEP MERGE ──────────────────────────────────────────────────────────────
// Deep merge: values from `incoming` overwrite `base`,
// but keys present in `base` and absent from `incoming` are preserved.
function deepMerge(base, incoming) {
  const result = { ...base };
  for (const [key, val] of Object.entries(incoming)) {
    if (val !== null && typeof val === 'object' && !Array.isArray(val)
        && typeof result[key] === 'object' && result[key] !== null && !Array.isArray(result[key])) {
      result[key] = deepMerge(result[key], val);
    } else {
      result[key] = val;
    }
  }
  return result;
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(200, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,X-Auth-Token' });
    return res.end();
  }

  const url = req.url.split('?')[0];

  // ── Serve panel.html ──────────────────────────────────────────────────────
  if (url === '/' || url === '/panel') {
    const html = fs.readFileSync(path.join(__dirname, 'panel.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // ── i18n — public, no auth required ──────────────────────────────────────
  // GET /api/i18n/{lang}  → serves language/{lang}.json directly
  // GET /api/i18n         → serves the active language from config (fallback: en-US)
  if (url.startsWith('/api/i18n')) {
    try {
      let lang = url.slice('/api/i18n'.length).replace(/^\//, '') || '';
      if (!lang) {
        const cfg = readJSON(FILES.config, {});
        lang = cfg.general?.language || 'en-US';
      }
      // Sanitize: only allow letters, digits, hyphens and underscores (e.g. pt-BR, en-US)
      lang = lang.replace(/[^a-zA-Z0-9_-]/g, '');
      const langFile = path.join(__dirname, 'language', `${lang}.json`);
      const data = fs.readFileSync(langFile, 'utf8');
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      return res.end(data);
    } catch {
      return json(res, {}, 200);
    }
  }

  // ── Auth endpoints (no auth required) ─────────────────────────────────────
  if (url === '/api/auth/login' && req.method === 'POST') {
    const ip = getClientIp(req);

    // Check block first — blocked IPs are rejected regardless of password
    if (isRateLimited(ip)) {
      const entry = loginAttempts.get(ip);
      const remainingSec = Math.ceil((entry.blockedUntil - Date.now()) / 1000);
      _log.warn(`[auth] blocked login attempt from ${ip} — ${remainingSec}s remaining`);
      return json(res, { ok: false, error: `too many attempts — wait ${remainingSec}s` }, 429);
    }

    const { password } = await bodyJSON(req);
    const auth = getAuth();

    if (hashPassword(password) === auth.hash) {
      recordSuccessfulLogin(ip);
      const token = newToken();
      sessions.set(token, { created: Date.now() });
      return json(res, { ok: true, token });
    }

    // Wrong password — record attempt (may trigger block)
    recordFailedLogin(ip);
    return json(res, { ok: false }, 401);
  }

  if (url === '/api/auth/check') {
    return json(res, { ok: checkToken(req) });
  }

  // ── Protected routes ──────────────────────────────────────────────────────
  if (!checkToken(req)) return unauthorized(res);

  if (url === '/api/auth/change-password' && req.method === 'POST') {
    const { current, novo } = await bodyJSON(req);
    const auth = getAuth();
    if (hashPassword(current) !== auth.hash) return json(res, { ok: false, error: 'incorrect password' });
    saveAuth({ hash: hashPassword(novo) });
    return json(res, { ok: true });
  }

  if (url === '/api/config') {
    if (req.method === 'GET') return json(res, readJSON(FILES.config));
    if (req.method === 'POST') {
      const incoming = await bodyJSON(req);
      const existing = readJSON(FILES.config, {});
      const merged   = deepMerge(existing, incoming);
      writeJSON(FILES.config, merged);
      // If the electrum server changed, activate lock (monitor will reconnect)
      if (incoming.electrum &&
          (incoming.electrum.host !== existing.electrum?.host ||
           incoming.electrum.port !== existing.electrum?.port)) {
        const rt = readJSON(FILES.runtime, {});
        const lockMsg = `reconnecting to server ${incoming.electrum.host}:${incoming.electrum.port}…`;
        // Clear electrum.error from previous cycles — panel only shows errors
        // written during *this* lock, not from past attempts.
        const prevElectrum = rt.electrum || {};
        writeJSON(FILES.runtime, {
          ...rt,
          electrum: { ...prevElectrum, error: undefined },
          lock: { active: true, msg: lockMsg, since: Date.now(), timeoutAt: Date.now() + 60_000 },
        });
        _log.info(`runtime lock activated: ${lockMsg}`);
      }
      // If gapLimit changed (and HD wallets exist), activate lock (monitor re-indexes)
      const prevGap = existing.monitor?.gapLimit;
      const newGap  = incoming.monitor?.gapLimit;
      if (newGap && prevGap && newGap !== prevGap) {
        const wList = readJSON(FILES.wallets, []);
        const hasHD = wList.some(w => w.descriptor && !w.descriptor.startsWith('addr('));
        if (hasHD) {
          const dir  = newGap > prevGap ? 'increasing' : 'reducing';
          const rt   = readJSON(FILES.runtime, {});
          const lockMsg = `${dir} gap limit ${prevGap} → ${newGap}…`;
          writeJSON(FILES.runtime, {
            ...rt,
            lock: { active: true, msg: lockMsg, since: Date.now(), timeoutAt: Date.now() + 180_000 },
          });
          _log.info(`runtime lock activated: ${lockMsg}`);
        }
      }
      return json(res, { ok: true });
    }
  }

  if (url === '/api/wallets') {
    if (req.method === 'GET') return json(res, readJSON(FILES.wallets, []));
    if (req.method === 'POST') {
      const incoming = await bodyJSON(req);
      const previous = readJSON(FILES.wallets, []);
      writeJSON(FILES.wallets, incoming);
      // Detect additions or removals to trigger runtime lock
      const prevNames = new Set(previous.map(w => w.name));
      const newNames  = new Set(incoming.map(w => w.name));
      const added   = incoming.filter(w => !prevNames.has(w.name));
      const removed = previous.filter(w => !newNames.has(w.name));
      if (added.length || removed.length) {
        const msg = added.length
          ? `indexing "${added[0].name}"…`
          : `removing "${removed[0].name}"…`;
        const rt = readJSON(FILES.runtime, {});
        writeJSON(FILES.runtime, {
          ...rt,
          lock: { active: true, msg, since: Date.now(), timeoutAt: Date.now() + 180_000 },
        });
        _log.info(`runtime lock activated: ${msg}`);
      }
      return json(res, { ok: true });
    }
  }

  if (url === '/api/servers') {
    if (req.method === 'GET') return json(res, readJSON(FILES.servers, []));
    if (req.method === 'POST') { writeJSON(FILES.servers, await bodyJSON(req)); return json(res, { ok: true }); }
  }

  if (url === '/api/state') return json(res, readJSON(FILES.state, {}));

  if (url === '/api/price') {
    const p = readJSON(FILES.runtime, {})?.price;
    if (!p?.usd) return json(res, { ok: false, error: 'price not yet available' });
    return json(res, { ok: true, usd: p.usd, updatedAt: p.updatedAt });
  }

  if (url === '/api/test-server' && req.method === 'POST') {
    const { host, port, tls: useTLS } = await bodyJSON(req);
    return json(res, await testElectrum(host, port, useTLS));
  }

  if (url === '/api/test-telegram' && req.method === 'POST') {
    const { token, chatId } = await bodyJSON(req);
    if (!token || !chatId) return json(res, { ok: false, error: 'token or chatId not provided' });
    return json(res, await testTelegram(token, chatId));
  }

  if (url === '/api/test-ntfy' && req.method === 'POST') {
    const { url: ntfyUrl, token } = await bodyJSON(req);
    return json(res, await testNtfy(ntfyUrl, token));
  }

  if (url === '/api/derive' && req.method === 'POST') {
    const { descriptor, startIndex = 0, count = 3 } = await bodyJSON(req);
    try {
      const normalized = normalizeDescriptor(descriptor);

      const isSingleAddress = normalized.startsWith('addr(');

      const deriveSpec = [];

      if (isSingleAddress) {
        // addr() is a fixed address — no derivation; a single spec is enough
        deriveSpec.push({ index: 0, chain: 0 });
      } else {
        for (let chain = 0; chain <= 1; chain++) {
          for (let i = startIndex; i < startIndex + count; i++) {
            deriveSpec.push({ index: i, chain });
          }
        }
      }

      const r = analyzeDescriptor(normalized, { hrp: 'bc', deriveSpec });
      if (r.errors.length) return json(res, { error: r.errors[0] });
      if (!r.addresses || r.addresses.length === 0)
        return json(res, { error: 'No addresses derived — check the descriptor.' });
      return json(res, { addresses: r.addresses, scriptType: r.scriptType, normalized });
    } catch(e) { return json(res, { error: e.message }, 400); }
  }

  // ── Check whether a wallet has been processed by the monitor ─────────────
  // Polls state.json to know when hot-reload finished subscribeAll for the
  // new wallet. Considers ready when state contains the wallet with at least
  // gapLimit ext + gapLimit chg addresses with balanceSat !== null
  // (addr() special case: just 1 address is enough).
  if (url === '/api/wallet-ready' && req.method === 'POST') {
    const { walletName, descriptor } = await bodyJSON(req);
    if (!walletName) return json(res, { ok: false, error: 'walletName required' });

    const cfg      = readJSON(FILES.config, {});
    const gapLimit = cfg.monitor?.gapLimit ?? 10;
    const isSingle = (descriptor || '').startsWith('addr(');
    // addr() has only 1 address; HD descriptor needs gapLimit ext + gapLimit chg
    const needed   = isSingle ? 1 : gapLimit * 2;

    const st     = readJSON(FILES.state, {});
    const wState = st[walletName];
    if (!wState) return json(res, { ready: false, processed: 0, needed });

    let processed = 0;
    for (const labelData of Object.values(wState)) {
      if (typeof labelData !== 'object') continue;
      for (const addrData of Object.values(labelData)) {
        if (addrData?.balanceSat !== null && addrData?.balanceSat !== undefined) processed++;
      }
    }

    return json(res, { ready: processed >= needed, processed, needed });
  }

  // ── Check whether rebalanceGap has finished for all wallets ──────────────
  // For gap increase: count processed vs expected addresses (N wallets × 2 chains × newGap).
  // For reduction: verify no wallet has addresses beyond the cutoff in state.
  if (url === '/api/gap-ready' && req.method === 'POST') {
    const { newGap } = await bodyJSON(req);
    if (!newGap || newGap < 1) return json(res, { ok: false, error: 'newGap required' });

    const wList  = readJSON(FILES.wallets, []);
    const st     = readJSON(FILES.state, {});

    // Only count wallets with HD descriptor (not addr())
    const hdWallets = wList.filter(w => w.descriptor && !w.descriptor.startsWith('addr('));
    if (!hdWallets.length) return json(res, { ready: true, processed: 0, needed: 0 });

    // needed = for each HD wallet, gapLimit ext + gapLimit chg addresses
    const needed = hdWallets.length * newGap * 2;
    let processed = 0;
    for (const w of hdWallets) {
      const wState = st[w.name];
      if (!wState) continue;
      for (const labelData of Object.values(wState)) {
        if (typeof labelData !== 'object') continue;
        for (const addrData of Object.values(labelData)) {
          if (addrData?.balanceSat !== null && addrData?.balanceSat !== undefined) processed++;
        }
      }
    }

    return json(res, { ready: processed >= needed, processed, needed });
  }

  // ── Runtime lock — blocks the panel UI during long operations ─────────────
  // monitor.js (or panel.js itself) writes { active, msg, since, timeoutAt }
  // to runtime.json under key "lock". The panel polls this route every 2s
  // and keeps the overlay visible while active===true.
  // A "timeoutAt" field ensures automatic release even if the process stalls.
  if (url === '/api/runtime-lock') {
    if (req.method === 'GET') {
      const rt = readJSON(FILES.runtime, {});
      const lock = rt.lock || { active: false };
      // Auto-expire: if timeoutAt exceeded, clear the lock
      if (lock.active && lock.timeoutAt && Date.now() > lock.timeoutAt) {
        lock.active = false;
        const updated = { ...rt, lock };
        writeJSON(FILES.runtime, updated);
        _log.warn('runtime lock expired by timeout — UI released automatically');
      }
      // Include electrum error when lock was released due to connection failure.
      const electrumError = (!lock.active && rt.electrum?.connected === false && rt.electrum?.error)
        ? rt.electrum.error : undefined;
      return json(res, electrumError ? { ...lock, electrumError } : lock);
    }
    if (req.method === 'POST') {
      const body = await bodyJSON(req);
      const rt = readJSON(FILES.runtime, {});
      // body: { active: bool, msg?: string, timeoutSec?: number }
      const lock = {
        active:    !!body.active,
        msg:       body.msg   || '',
        since:     body.active ? Date.now() : null,
        timeoutAt: body.active
          ? Date.now() + (body.timeoutSec || 180) * 1000
          : null,
      };
      writeJSON(FILES.runtime, { ...rt, lock });
      return json(res, { ok: true, lock });
    }
  }

  if (url === '/api/server-status') {
    // Read status written by monitor.js into runtime.json — no TCP connection
    const rt = readJSON(FILES.runtime, {});
    if (rt.electrum) {
      return json(res, {
        ok:      rt.electrum.connected === true,
        host:    rt.electrum.host,
        port:    rt.electrum.port,
        version: rt.electrum.connected ? 'monitor active' : undefined,
        error:   rt.electrum.error,
        since:   rt.electrum.since,
      });
    }
    // Fallback: monitor not yet started — test directly
    const cfg = readJSON(FILES.config);
    if (!cfg.electrum) return json(res, { ok: false, error: 'no server configured' });
    const { host, port, tls } = cfg.electrum;
    return json(res, await testElectrum(host, port, tls));
  }

  if (url === '/api/pricehistory') {
    return json(res, readJSON(FILES.priceHistory, []));
  }

  if (url === '/api/txhistory') {
    return json(res, readJSON(FILES.txHistory, {}));
  }

  // ── Fee estimate via Electrum (runtime.json) ─────────────────────────────
  if (url === '/api/fee') {
    const rt   = readJSON(FILES.runtime, {});
    const fees = rt.fees;
    if (fees && fees.fastestFee) {
      return json(res, { ok: true, fees });
    }
    return json(res, { ok: false, error: 'fees not yet available — wait for the next monitor ping' });
  }

  // ── Per-wallet color label ───────────────────────────────────────────────
  if (url.startsWith('/api/wallet-label/') && req.method === 'POST') {
    if (!checkToken(req)) return unauthorized(res);
    const walletName = decodeURIComponent(url.slice('/api/wallet-label/'.length));
    const { label, color } = await bodyJSON(req);
    const wList = readJSON(FILES.wallets, []);
    const w = wList.find(x => x.name === walletName);
    if (!w) return json(res, { ok: false, error: 'wallet not found' }, 404);
    w.label = label || '';
    w.labelColor = color || '';
    writeJSON(FILES.wallets, wList);
    return json(res, { ok: true });
  }

  res.writeHead(404); res.end('not found');
});

server.listen(PANEL_PORT, () => {
  _log.info(`BitTrack Panel → http://localhost:${PANEL_PORT}`);
  _log.info(`Default password: "admin" (change under Settings → Panel password)`);
});