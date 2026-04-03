/**
 * BitTrack Panel — servidor Express para o painel web
 */

'use strict';

// ─── LOG COM TIMESTAMP ────────────────────────────────────────────────────────
// Usa o console original (sem patch) e adiciona [PANEL] manualmente
function nowStr() {
  const cfg = readJSON(FILES.config, {})?.general || {};
  return '[' + new Date().toLocaleString(cfg.dateLocale || 'pt-BR', { timeZone: cfg.timezone || 'UTC', hour12: false }).replace(/\//g, '-').replace(',', '').replace(/\s+/, ' ').slice(0, 19) + ']';
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

// Sessões em memória: token → { created }
const sessions = new Map();

// ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'BitTrack_salt').digest('hex');
}

function getAuth() {
  try { return JSON.parse(fs.readFileSync(FILES.auth, 'utf8')); }
  catch { return { hash: hashPassword('admin') }; } // senha padrão
}

function saveAuth(data) {
  fs.writeFileSync(FILES.auth, JSON.stringify(data, null, 2));
}

function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

function checkToken(req) {
  const token = req.headers['x-auth-token'] || '';
  return sessions.has(token);
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function readJSON(file, fallback = {}) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

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
  json(res, { error: 'não autorizado' }, 401);
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
        } catch { clearTimeout(timeout); sock.destroy(); resolve({ ok: false, error: 'resposta inválida' }); }
      }
    });
    sock.on('error', e => { clearTimeout(timeout); resolve({ ok: false, error: e.message }); });
    if (!useTLS) sock.on('connect', onConnect);
  });
}

// ─── TEST TELEGRAM ─────────────────────────────────────────────────────────────
function testTelegram(token, chatId) {
  return new Promise(resolve => {
    const text = '🔔 BitTrack Panel — teste de conexão OK';
    const body = JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' });
    const req  = https.request({
      hostname: 'api.telegram.org', path: `/bot${token}/sendMessage`,
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try { const r = JSON.parse(d); r.ok ? resolve({ ok: true }) : resolve({ ok: false, error: r.description }); }
        catch { resolve({ ok: false, error: 'resposta inválida' }); }
      });
    });
    req.on('error', e => resolve({ ok: false, error: e.message }));
    req.write(body); req.end();
  });
}

// ─── TEST NTFY ────────────────────────────────────────────────────────────────
function testNtfy(url, token) {
  return new Promise(resolve => {
    if (!url) return resolve({ ok: false, error: 'URL não informada' });
    let u;
    try { u = new URL(url); } catch { return resolve({ ok: false, error: 'URL inválida' }); }
    const text    = '🔔 BitTrack — teste de conexão OK';
    const body    = Buffer.from(text, 'utf8');
    const headers = {
      'Content-Type':   'text/plain',
      'Content-Length': body.length,
      'Markdown':       'yes',
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const req = https.request({
      hostname: u.hostname,
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

// Adiciona /<0;1>/* após chaves pub que ainda não têm derivPath,
// Garante vírgula separadora entre chaves adjacentes e adiciona /<0;1>/*
function addDerivPaths(str) {
  let r = str
    // Passo 1: remove espaço entre ] e a chave seguinte: "] Zpub" → "]Zpub"
    .replace(/(\])\s+(?=[xyYzZuUvVtT]pub)/g, ']')
    // Passo 2: espaço entre fim de chave e início de próxima ([fp] ou chave) → ','
    .replace(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)\s+(?=\[|[xyYzZuUvVtT]pub)/g, '$1,')
    // Passo 3: espaço entre derivPath existente e próxima chave → ','
    .replace(/(\/\*)\s+(?=\[|[xyYzZuUvVtT]pub)/g, '$1,')
    // Passo 4: garante vírgula entre /<0;1>/* e [ quando não há separador
    .replace(/(\/\*)(?=\[)/g, '$1,');
  // Passo 5: adiciona /<0;1>/* onde ainda não há path
  r = r.replace(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)(?!\/)/g, m => m + '/<0;1>/*');
  return r;
}

// Tipo de script pelo prefixo da chave (ypub/zpub/Ypub/Zpub têm semântica definida)
// isMultisig: ypub em multisig → P2SH-WSH (Ypub-equivalente); zpub em multisig → P2WSH
function detectKeyType(key, isMultisig) {
  if (/^ypub|^upub/.test(key)) return isMultisig ? 'P2SH-WSH' : 'P2SH-WPKH';
  if (/^zpub|^vpub/.test(key)) return isMultisig ? 'P2WSH'    : 'P2WPKH';
  if (/^Ypub|^Upub/.test(key)) return 'P2SH-WSH';
  if (/^Zpub|^Vpub/.test(key)) return 'P2WSH';
  return null; // xpub/tpub — usa path de derivação
}

// Tipo de script pelo caminho de derivação (BIP44/49/84/86/48)
function inferFromPath(str) {
  if (/86h|86[']/.test(str)) return 'P2TR';
  if (/84h|84[']/.test(str)) return 'P2WPKH';
  if (/49h|49[']/.test(str)) return 'P2SH-WPKH';
  if (/48h|48[']/.test(str)) return 'P2WSH';
  if (/44h|44[']/.test(str)) return 'P2PKH';
  // xpub sem nenhum path BIP → Legacy P2PKH (xpub é formato original pré-BIP84)
  return 'P2PKH';
}

// Corrige vírgulas faltando entre chaves dentro de um descritor já com wrapper
// Ex: xpub.../<0;1>/*[fp]xpub → xpub.../<0;1>/*,[fp]xpub
function fixMissingCommas(str) {
  return str
    .replace(/(\/\*)\s*(?=\[)/g,  '$1,')   // /*[  →  /*,[
    .replace(/(\/\*)\s*(?=[xyYzZuUvVtT]pub)/g, '$1,'); // /* zpub → /*,zpub
}

function normalizeDescriptor(desc) {
  // Normaliza whitespace (newlines/tabs → espaço simples)
  const clean = desc.trim().split('#')[0].trim()
    .replace(/[\r\n\t]+/g, ' ')   // newlines → espaço
    .replace(/\s{2,}/g, ' ')        // múltiplos espaços → um
    .replace(/\]\s+([xyYzZuUvVtT])/g, ']$1')  // remove espaço entre ] e chave
    .replace(/\[\s+/g, '[');        // remove espaço após [

  // 1. Endereço simples → addr()
  if (isBitcoinAddress(clean)) return `addr(${clean})`;

  // 2. Já tem wrapper completo
  const hasWrapper   = /^(tr|wpkh|pkh|sh|wsh|addr|combo)\(/.test(clean);
  const hasDerivPath = /<\d+;\d+>\/\*/.test(clean) || /\/\d+\/\*/.test(clean);
  if (hasWrapper && hasDerivPath)  return fixMissingCommas(clean); // caso 4: completo
  if (hasWrapper && !hasDerivPath) return addDerivPaths(clean);   // caso 3: falta path

  // 3. Sem wrapper — detecta tipo e constrói o descritor completo
  const keys       = [...clean.matchAll(/([xyYzZuUvVtT]pub[a-zA-Z0-9]+)/g)].map(m => m[1]);
  if (!keys.length) return clean; // não reconhecido — devolve limpo

  const isMultisig = keys.length > 1;
  const keyType    = detectKeyType(keys[0], isMultisig);
  const scriptType = keyType || inferFromPath(clean);
  const withPaths  = addDerivPaths(clean);

  if (isMultisig) {
    // Extrai M do início: "2 [fp]Xpub..." ou "2,[fp]Xpub..."
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
    // Ypub/Upub sozinhos (sem par) ainda são P2SH-WSH — envolve com sh(wsh(...))
    case 'P2SH-WSH':  return `sh(wsh(${withPaths}))`;
    case 'P2WSH':     return `wsh(${withPaths})`;
    default:          return `pkh(${withPaths})`; // fallback: xpub desconhecido → legacy
  }
}

// ─── DEEP MERGE ──────────────────────────────────────────────────────────────
// Merge profundo: valores do `incoming` sobrescrevem o `base`,
// mas chaves presentes em `base` e ausentes em `incoming` são preservadas.
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

  // ── Auth endpoints (sem autenticação) ─────────────────────────────────────
  if (url === '/api/auth/login' && req.method === 'POST') {
    const { password } = await bodyJSON(req);
    const auth = getAuth();
    if (hashPassword(password) === auth.hash) {
      const token = newToken();
      sessions.set(token, { created: Date.now() });
      return json(res, { ok: true, token });
    }
    return json(res, { ok: false }, 401);
  }

  if (url === '/api/auth/check') {
    return json(res, { ok: checkToken(req) });
  }

  // ── Rotas protegidas ──────────────────────────────────────────────────────
  if (!checkToken(req)) return unauthorized(res);

  if (url === '/api/auth/change-password' && req.method === 'POST') {
    const { current, novo } = await bodyJSON(req);
    const auth = getAuth();
    if (hashPassword(current) !== auth.hash) return json(res, { ok: false, error: 'senha atual incorreta' });
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
      // Se o servidor electrum mudou, ativa lock (monitor reconecta)
      if (incoming.electrum &&
          (incoming.electrum.host !== existing.electrum?.host ||
           incoming.electrum.port !== existing.electrum?.port)) {
        const rt = readJSON(FILES.runtime, {});
        const lockMsg = `reconectando ao servidor ${incoming.electrum.host}:${incoming.electrum.port}…`;
        // Limpa electrum.error de ciclos anteriores — o painel só exibe erro
        // se foi gravado durante *este* lock, não de uma tentativa passada.
        const prevElectrum = rt.electrum || {};
        writeJSON(FILES.runtime, {
          ...rt,
          electrum: { ...prevElectrum, error: undefined },
          lock: { active: true, msg: lockMsg, since: Date.now(), timeoutAt: Date.now() + 60_000 },
        });
        _log.info(`runtime lock ativado: ${lockMsg}`);
      }
      // Se o gapLimit mudou (e existem wallets HD), ativa lock (monitor re-indexa)
      const prevGap = existing.monitor?.gapLimit;
      const newGap  = incoming.monitor?.gapLimit;
      if (newGap && prevGap && newGap !== prevGap) {
        const wList = readJSON(FILES.wallets, []);
        const hasHD = wList.some(w => w.descriptor && !w.descriptor.startsWith('addr('));
        if (hasHD) {
          const dir  = newGap > prevGap ? 'aumentando' : 'reduzindo';
          const rt   = readJSON(FILES.runtime, {});
          const lockMsg = `${dir} gap limit ${prevGap} → ${newGap}…`;
          writeJSON(FILES.runtime, {
            ...rt,
            lock: { active: true, msg: lockMsg, since: Date.now(), timeoutAt: Date.now() + 180_000 },
          });
          _log.info(`runtime lock ativado: ${lockMsg}`);
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
      // Detecta se houve adição ou remoção para acionar o lock de runtime
      const prevNames = new Set(previous.map(w => w.name));
      const newNames  = new Set(incoming.map(w => w.name));
      const added   = incoming.filter(w => !prevNames.has(w.name));
      const removed = previous.filter(w => !newNames.has(w.name));
      if (added.length || removed.length) {
        const msg = added.length
          ? `indexando "${added[0].name}"…`
          : `removendo "${removed[0].name}"…`;
        const rt = readJSON(FILES.runtime, {});
        writeJSON(FILES.runtime, {
          ...rt,
          lock: { active: true, msg, since: Date.now(), timeoutAt: Date.now() + 180_000 },
        });
        _log.info(`runtime lock ativado: ${msg}`);
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
    if (!p?.usd) return json(res, { ok: false, error: 'preço ainda não disponível' });
    return json(res, { ok: true, usd: p.usd, updatedAt: p.updatedAt });
  }

  if (url === '/api/test-server' && req.method === 'POST') {
    const { host, port, tls: useTLS } = await bodyJSON(req);
    return json(res, await testElectrum(host, port, useTLS));
  }

  if (url === '/api/test-telegram' && req.method === 'POST') {
    const { token, chatId } = await bodyJSON(req);
    if (!token || !chatId) return json(res, { ok: false, error: 'token ou chatId não informados' });
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
        // addr() é um endereço fixo — não há derivação; um único spec é suficiente
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
        return json(res, { error: 'Nenhum endereço derivado — verifique o descritor.' });
      return json(res, { addresses: r.addresses, scriptType: r.scriptType, normalized });
    } catch(e) { return json(res, { error: e.message }, 400); }
  }

  // ── Verifica se uma wallet já foi processada pelo monitor ─────────────────
  // Faz polling do state.json para saber quando o hot-reload terminou o
  // subscribeAll da nova wallet. Considera pronto quando o state contém a
  // wallet com pelo menos gapLimit endereços ext + gapLimit endereços chg
  // com balanceSat !== null (addr() é caso especial: basta 1 endereço).
  if (url === '/api/wallet-ready' && req.method === 'POST') {
    const { walletName, descriptor } = await bodyJSON(req);
    if (!walletName) return json(res, { ok: false, error: 'walletName obrigatório' });

    const cfg      = readJSON(FILES.config, {});
    const gapLimit = cfg.monitor?.gapLimit ?? 10;
    const isSingle = (descriptor || '').startsWith('addr(');
    // addr() tem só 1 endereço; descritor HD precisa de gapLimit ext + gapLimit chg
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

  // ── Verifica se o rebalanceGap já terminou para todas as wallets ──────────
  // Para aumento de gap: conta endereços processados vs. esperados (N wallets × 2 chains × newGap).
  // Para redução: verifica que nenhuma wallet tem endereços além do cutoff no state.
  if (url === '/api/gap-ready' && req.method === 'POST') {
    const { newGap } = await bodyJSON(req);
    if (!newGap || newGap < 1) return json(res, { ok: false, error: 'newGap obrigatório' });

    const wList  = readJSON(FILES.wallets, []);
    const st     = readJSON(FILES.state, {});

    // Só conta wallets com descritor HD (não addr())
    const hdWallets = wList.filter(w => w.descriptor && !w.descriptor.startsWith('addr('));
    if (!hdWallets.length) return json(res, { ready: true, processed: 0, needed: 0 });

    // needed = para cada wallet HD, gapLimit endereços ext + gapLimit chg
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

  // ── Runtime lock — bloqueia a UI do painel durante operações longas ──────────
  // O monitor.js (ou o próprio panel.js) grava { active, msg, since, timeoutAt }
  // em runtime.json sob a chave "lock".  O painel faz polling desta rota a cada
  // 2 s e mantém o overlay visível enquanto active===true.
  // Um campo "timeoutAt" garante liberação automática mesmo se o processo travar.
  if (url === '/api/runtime-lock') {
    if (req.method === 'GET') {
      const rt = readJSON(FILES.runtime, {});
      const lock = rt.lock || { active: false };
      // Auto-expire: se ultrapassou timeoutAt, limpa o lock
      if (lock.active && lock.timeoutAt && Date.now() > lock.timeoutAt) {
        lock.active = false;
        const updated = { ...rt, lock };
        writeJSON(FILES.runtime, updated);
        _log.warn('runtime lock expirado por timeout — UI liberada automaticamente');
      }
      // Inclui erro do electrum quando o lock foi liberado por falha de conexão.
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
        msg:       body.msg   || (body.active ? 'aguarde...' : ''),
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
    // Lê status gravado pelo monitor.js no runtime.json — sem abrir conexão TCP
    const rt = readJSON(FILES.runtime, {});
    if (rt.electrum) {
      return json(res, {
        ok:      rt.electrum.connected === true,
        host:    rt.electrum.host,
        port:    rt.electrum.port,
        version: rt.electrum.connected ? 'monitor ativo' : undefined,
        error:   rt.electrum.error,
        since:   rt.electrum.since,
      });
    }
    // Fallback: monitor não iniciou ainda — testa diretamente
    const cfg = readJSON(FILES.config);
    if (!cfg.electrum) return json(res, { ok: false, error: 'nenhum servidor configurado' });
    const { host, port, tls } = cfg.electrum;
    return json(res, await testElectrum(host, port, tls));
  }

  if (url === '/api/pricehistory') {
    return json(res, readJSON(FILES.priceHistory, []));
  }

  if (url === '/api/txhistory') {
    return json(res, readJSON(FILES.txHistory, {}));
  }

  // ── Fee estimado via Electrum (runtime.json) ────────────────────────────
  if (url === '/api/fee') {
    const rt   = readJSON(FILES.runtime, {});
    const fees = rt.fees;
    if (fees && fees.fastestFee) {
      return json(res, { ok: true, fees });
    }
    return json(res, { ok: false, error: 'fees ainda não disponíveis — aguarde o próximo ping do monitor' });
  }

  // ── Label por wallet ──────────────────────────────────────────────────────
  if (url.startsWith('/api/wallet-label/') && req.method === 'POST') {
    if (!checkToken(req)) return unauthorized(res);
    const walletName = decodeURIComponent(url.slice('/api/wallet-label/'.length));
    const { label, color } = await bodyJSON(req);
    const wList = readJSON(FILES.wallets, []);
    const w = wList.find(x => x.name === walletName);
    if (!w) return json(res, { ok: false, error: 'carteira não encontrada' }, 404);
    w.label = label || '';
    w.labelColor = color || '';
    writeJSON(FILES.wallets, wList);
    return json(res, { ok: true });
  }

  res.writeHead(404); res.end('not found');
});

server.listen(PANEL_PORT, () => {
  _log.info(`BitTrack Panel → http://localhost:${PANEL_PORT}`);
  _log.info(`Senha padrão: "admin" (altere em Configuração → Senha do painel)`);
});