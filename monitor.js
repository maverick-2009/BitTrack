/**
 * BitTrack Monitor v5 — Electrum Server
 *
 * Fluxo:
 *   1. Derive addresses via descriptor (BIP380/BIP389/Miniscript)
 *   2. Convert each address to scripthash (reversed SHA256 of scriptPubKey)
 *   3. blockchain.scripthash.subscribe → push em tempo real
 *   4. On change: get_history → transaction.get → classifyTx
 *   5. Classify: received / sent / sent+change / consolidation
 *   6. Notify Telegram — single message per TXID (deduplication)
 *   7. Automatic gap limit for external and change (no duplicates)
 */

'use strict';

const { analyzeDescriptor, scriptToScriptHash } = require('./descriptor-parser');
const net            = require('net');
const tls            = require('tls');
const https          = require('https');
const fs             = require('fs');
const path           = require('path');
const { createHash } = require('crypto');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

// ─── CONFIG ───────────────────────────────────────────────────────────────────
// Complete config structure with all default values.
// Used both to create the file from scratch and to fill in missing fields.
const CONFIG_DEFAULTS = {
  electrum: {
    name: 'Emzy.de',
    host: 'electrum.emzy.de',
    port: 50002,
    tls:  true,
  },
  telegram: {
    enabled: false,
    token:   '',
    chatId:  '',
  },
  ntfy: {
    enabled: false,
    url:     '',
    token:   '',
  },
  general: {
    mempoolExplorer: 'https://mempool.emzy.de/',
    currency:        'USD',
    timezone:        'UTC',
    dateLocale:      'en-US',
    language:        'en-US',
    panelPort:       8585,
  },
  monitor: {
    gapLimit:              10,
    maxIndex:              1000,
    pingIntervalSec:       60,
    subscribeDelayMs:      3,
    priceApis:               ['coingecko', 'binance', 'blockchain.info'],
    priceCheckIntervalSec:   300,
    priceRefMaxDeviationPct: 20,  // maximum allowed deviation for priceReference (%)
    priceThresholdMinPct:    0.5,   // minimum threshold % of current price
    priceThresholdMaxPct:    50,  // maximum threshold % of current price
  },
  notifications: {
    mempoolPending:    true,
    txConfirmed:       true,
    everyBlock:        false,
    blockIntervalMin:  0,
    priceChange:       false,
    priceThresholdPct:  1,    // price change threshold % of current price
    priceReference:  null,   // null = uses current price as reference
  },
};

// Deep merge: fills missing fields in `target` with values from `defaults`.
// Never overwrites existing values — only adds what is missing.
function deepMergeDefaults(target, defaults) {
  const result = { ...target };
  for (const [key, val] of Object.entries(defaults)) {
    if (!(key in result)) {
      result[key] = val;
    } else if (val !== null && typeof val === 'object' && !Array.isArray(val)
               && typeof result[key] === 'object' && result[key] !== null) {
      result[key] = deepMergeDefaults(result[key], val);
    }
  }
  return result;
}

// Reads config.json, fills missing fields with defaults and rewrites if needed.
// Called once at boot via ensureConfig() and then read on demand via getCFG().
function ensureConfig() {
  const cfgFile = path.join(dataDir, 'config.json');
  let fc = {};
  let existed = true;
  try {
    fc = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  } catch {
    existed = false;
  }

  const merged = deepMergeDefaults(fc, CONFIG_DEFAULTS);
  const mergedStr = JSON.stringify(merged, null, 2);
  const originalStr = JSON.stringify(fc, null, 2);

  if (!existed || mergedStr !== originalStr) {
    fs.writeFileSync(cfgFile, mergedStr);
    if (!existed) {
      log.info('config.json created with default values — fill in electrum and telegram before starting');
    } else {
      log.info('config.json updated — missing fields filled with default values');
    }
  }
}

// Last valid config read from disk — used as fallback if file is corrupted
let _lastValidConfig = null;

// Reads config.json from disk — called whenever updated values are needed.
// Does not use in-memory cache so changes made via the panel are
// reflected immediately without restarting the process.
function loadConfig() {
  const cfgFile = path.join(dataDir, 'config.json');
  let fc = {};
  try {
    const raw = fs.readFileSync(cfgFile, 'utf8');
    fc = JSON.parse(raw);
    _lastValidConfig = fc; // save last valid
  } catch {
    // Invalid JSON (file being written) — silently use last valid config
    if (_lastValidConfig) fc = _lastValidConfig;
  }
  const g = fc.general       || CONFIG_DEFAULTS.general;
  const m = fc.monitor       || CONFIG_DEFAULTS.monitor;
  const n = fc.notifications || CONFIG_DEFAULTS.notifications;
  return {
    electrum:              fc.electrum || CONFIG_DEFAULTS.electrum,
    telegram:              fc.telegram || CONFIG_DEFAULTS.telegram,
    // general
    mempoolExplorer:       g.mempoolExplorer,
    dateLocale:            g.dateLocale,
    currency:              g.currency,
    timezone:              g.timezone,
    language:              g.language || 'en-US',
    // monitor
    gapLimit:                m.gapLimit                ?? CONFIG_DEFAULTS.monitor.gapLimit,
    maxIndex:                m.maxIndex                ?? CONFIG_DEFAULTS.monitor.maxIndex,
    pingInterval:           (m.pingIntervalSec         ?? CONFIG_DEFAULTS.monitor.pingIntervalSec) * 1000,
    subscribeDelayMs:        m.subscribeDelayMs        ?? CONFIG_DEFAULTS.monitor.subscribeDelayMs,
    priceApis:               m.priceApis               ?? CONFIG_DEFAULTS.monitor.priceApis,
    priceCheckIntervalSec:   m.priceCheckIntervalSec   ?? CONFIG_DEFAULTS.monitor.priceCheckIntervalSec,
    priceRefMaxDeviationPct: m.priceRefMaxDeviationPct ?? CONFIG_DEFAULTS.monitor.priceRefMaxDeviationPct,
    priceThresholdMinPct:    m.priceThresholdMinPct    ?? CONFIG_DEFAULTS.monitor.priceThresholdMinPct,
    priceThresholdMaxPct:    m.priceThresholdMaxPct    ?? CONFIG_DEFAULTS.monitor.priceThresholdMaxPct,
    notifications:         n,
    ntfy:                  fc.ntfy || CONFIG_DEFAULTS.ntfy || {},
    reconnectDelay:        10000,
    stateFile:             path.join(dataDir, 'state.json'),
    walletsFile:           path.join(dataDir, 'wallets.json'),
  };
}
// CFG is read from disk on demand — use getCFG() instead of CFG directly
// to ensure values are always up to date.
function getCFG() { return loadConfig(); }
// Keeps a copy of the active electrum for server-change detection
let _activeElectrumKey = '';
function electrumKey(e) { return `${e.host}:${e.port}:${e.tls}`; }
const CFG = getCFG(); // used only for initialization

// ─── I18N ─────────────────────────────────────────────────────────────────────
// Loads language/{lang}.json on demand and caches per locale.
// The panel loads the same files via /api/i18n/{lang} and handles UI translation.
const _i18nCache = {};

function loadLang(lang) {
  if (_i18nCache[lang]) return _i18nCache[lang];
  try {
    const file = path.join(__dirname, 'language', `${lang}.json`);
    _i18nCache[lang] = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    _i18nCache[lang] = null; // mark as missing so we don't retry every call
  }
  return _i18nCache[lang];
}

// Returns the translated string for key, interpolating {var} placeholders.
// Falls back to en-US, then to the raw key if nothing is found.
function t(key, vars = {}) {
  const lang = getCFG().language || 'en-US';
  const dict = loadLang(lang) || loadLang('en-US') || {};
  let str = dict[key] ?? (loadLang('en-US') || {})[key] ?? key;
  for (const [k, v] of Object.entries(vars)) {
    str = str.replaceAll(`{${k}}`, v ?? '');
  }
  return str;
}
const RUNTIME_FILE       = path.join(dataDir, 'runtime.json');
const PRICE_HISTORY_FILE = path.join(dataDir, 'historicalprice.json');
const TX_HISTORY_FILE    = path.join(dataDir, 'txhistory.json');

// runtime.json — volatile data written by the monitor in real time.
// Never watched by fs.watchFile, so it does not cause restarts.
// Current structure: { price: { usd, updatedAt }, ... }
function readRuntime() {
  try { return JSON.parse(fs.readFileSync(RUNTIME_FILE, 'utf8')); }
  catch { return {}; }
}

// ─── PRICE HISTORY ──────────────────────────────────────────────────────
// Writes each price point to data/historicalprice.json
// Format: array of { t: timestamp_ms, p: price }
// Capped at 8640 points (30 days × 288 points/day at 5 min intervals)
const PRICE_HISTORY_MAX = 8640;

function appendPriceHistory(price) {
  try {
    const currency = getCFG().currency || 'USD';
    let history = [];
    try { history = JSON.parse(fs.readFileSync(PRICE_HISTORY_FILE, 'utf8')); }
    catch { history = []; }
    if (!Array.isArray(history)) history = [];
    history.push({ t: Date.now(), p: price, c: currency });
    if (history.length > PRICE_HISTORY_MAX) history = history.slice(-PRICE_HISTORY_MAX);
    fs.writeFileSync(PRICE_HISTORY_FILE, JSON.stringify(history));
  } catch(e) { log.warn(`appendPriceHistory: ${e.message}`); }
}

// ─── TRANSACTION HISTORY ──────────────────────────────────────────────────
// Writes each classified transaction to data/txhistory.json
// Structure: { [walletName]: { txids: { [txid]: { type, valueSat, feeSat, height, ts, mempool, addresses } } } }
// Deduplication via O(1) lookup on the txids object — never reprocesses existing entries.
// Maximum of 500 txids per wallet (oldest removed first).

const TX_HISTORY_MAX = 500;

function readTxHistory() {
  try { return JSON.parse(fs.readFileSync(TX_HISTORY_FILE, 'utf8')); }
  catch { return {}; }
}

function writeTxHistory(data) {
  try { fs.writeFileSync(TX_HISTORY_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { log.warn(`writeTxHistory: ${e.message}`); }
}

// Returns true if the txid is already recorded for that wallet
function txHistoryHas(walletName, txid) {
  try {
    const h = readTxHistory();
    return !!(h[walletName]?.txids?.[txid]);
  } catch { return false; }
}

// Records a classified transaction in history.
// classification, txid: required
// height: block number (null = mempool)
// isPending: bool
// histEntry: getHistory entry (may have .time for real timestamp)
function appendTxHistory(classification, txid, height, isPending, histEntry) {
  try {
    const { type, walletName } = classification;
    const h = readTxHistory();
    if (!h[walletName]) h[walletName] = { txids: {} };
    if (!h[walletName].txids) h[walletName].txids = {};

    // Deduplication — never reprocesses
    if (h[walletName].txids[txid]) {
      // Update only if it was mempool and is now confirmed
      if (h[walletName].txids[txid].mempool && !isPending && height) {
        h[walletName].txids[txid].mempool = false;
        h[walletName].txids[txid].height  = height;
        writeTxHistory(h);
      }
      return;
    }

    let valueSat = 0, feeSat = 0, addresses = [];
    if (type === 'received') {
      valueSat  =  classification.valueSat  || 0;
      addresses =  (classification.destinations || []).map(d => d.address);
    } else if (type === 'sent') {
      feeSat    =   classification.feeSats  || 0;
      valueSat  = -(classification.sentSats || 0) - feeSat;
      addresses =  (classification.destinations || []).map(d => d.address);
    } else if (type === 'sent_with_change') {
      feeSat    =   classification.feeSats  || 0;
      valueSat  = -(classification.sentSats || 0) - feeSat;
      addresses =  (classification.destinations || []).map(d => d.address);
    } else if (type === 'consolidation') {
      valueSat  =  classification.outputSats || 0;
      addresses =  (classification.destinations || []).map(d => d.address);
    }

    // Timestamp: prefers .time from Electrum (unix seconds), otherwise Date.now()
    const ts = histEntry?.time ? histEntry.time * 1000 : (isPending ? Date.now() : null);

    h[walletName].txids[txid] = {
      type,
      valueSat,
      feeSat,
      height:  height || null,
      ts,
      mempool: !!isPending,
      addresses,
    };

    // Cap at TX_HISTORY_MAX per wallet (remove oldest by height/ts)
    const entries = Object.entries(h[walletName].txids);
    if (entries.length > TX_HISTORY_MAX) {
      entries.sort(([, a], [, b]) => {
        const ha = a.height || 9999999, hb = b.height || 9999999;
        if (ha !== hb) return ha - hb;
        return (a.ts || 0) - (b.ts || 0);
      });
      const toRemove = entries.slice(0, entries.length - TX_HISTORY_MAX);
      for (const [id] of toRemove) delete h[walletName].txids[id];
    }

    writeTxHistory(h);
  } catch(e) { log.warn(`appendTxHistory: ${e.message}`); }
}

// Saves price reference to notifications.priceReference in config.json
// without overwriting the rest — fs.watchFile will detect but hotReloadConfig
// will ignore it since only priceReference changed (not a server change).
function saveThresholdPct(pct) {
  try {
    const cfgFile = path.join(dataDir, 'config.json');
    const data    = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
    if (!data.notifications) data.notifications = {};
    data.notifications.priceThresholdPct = pct;
    fs.writeFileSync(cfgFile, JSON.stringify(data, null, 2));
  } catch(e) { log.warn(`saveThresholdPct: ${e.message}`); }
}

function savePriceReference(price) {
  try {
    const cfgFile = path.join(dataDir, 'config.json');
    const data    = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
    if (!data.notifications) data.notifications = {};
    data.notifications.priceReference = price;
    fs.writeFileSync(cfgFile, JSON.stringify(data, null, 2));
  } catch(e) { log.warn(`savePriceReference: ${e.message}`); }
}

function writeRuntime(patch) {
  const data = readRuntime();
  const merged = { ...data, ...patch };
  try { fs.writeFileSync(RUNTIME_FILE, JSON.stringify(merged, null, 2)); }
  catch(e) { log.warn(`writeRuntime: ${e.message}`); }
}

// Updates only the lock message without touching active/timeoutAt
// Used during indexing loops to show progress on the panel overlay
function updateLockMsg(msg) {
  const data = readRuntime();
  if (!data.lock?.active) return; // only update if lock is still active
  data.lock.msg = msg;
  try { fs.writeFileSync(RUNTIME_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { log.warn(`updateLockMsg: ${e.message}`); }
}

// ─── FEES VIA ELECTRUM ───────────────────────────────────────────────────────
// Fetches fee histogram from Electrum and computes fast/medium/slow estimates.
// The histogram is an array of [feeRate, vsize] sorted by feeRate descending.
// Strategy: accumulate vsize until 25% (fast), 50% (medium), 75% (slow)
// of total. feeRate in sat/vB (already in Electrum's correct format).
async function fetchAndSaveFees(electrum) {
  try {
    // 1. Fetch official Bitcoin Core fee estimates (via Electrum)
    // n=2 (~20 min), n=5 (~50 min), n=10 (~1h 40min)
    const [f2, f5, f10] = await Promise.all([
      electrum.call('blockchain.estimatefee', [2]),
      electrum.call('blockchain.estimatefee', [5]),
      electrum.call('blockchain.estimatefee', [10])
    ]);

    const toSatVb = (btcKb) => (btcKb && btcKb > 0) ? Math.ceil(btcKb * 100000) : null;

    let fast = toSatVb(f2);
    let med  = toSatVb(f5);
    let slow = toSatVb(f10);

    // 2. Fallback: if estimatefee fails (-1), use the histogram as plan B
    if (!fast || !med || !slow) {
      const histogram = await electrum.getFeeHistogram();
      if (Array.isArray(histogram) && histogram.length > 0) {
        const total = histogram.reduce((s, [, v]) => s + v, 0);
        let acc = 0;
        for (const [fee, vsize] of histogram) {
          acc += vsize;
          if (fast === null && acc >= total * 0.25) fast = Math.round(fee);
          if (med  === null && acc >= total * 0.50) med  = Math.round(fee);
          if (slow === null && acc >= total * 0.75) slow = Math.round(fee);
        }
      }
    }

    // 3. Final sanity check
    // If all fail, assume 1 sat/vB. If values exist, enforce the hierarchy.
    fast = Math.max(1, fast ?? 1);
    med  = Math.max(1, med  ?? fast);
    slow = Math.max(1, slow ?? med);

    // Logical ordering: fast >= med >= slow
    const fastestFee  = Math.max(fast, med, slow);
    const halfHourFee = Math.max(med, slow);
    const hourFee     = slow;

    writeRuntime({
      fees: {
        fastestFee,
        halfHourFee,
        hourFee,
        updatedAt: Date.now(),
      }
    });

    log.info(`  [fees] fast=${fastestFee} medium=${halfHourFee} slow=${hourFee} sat/vB`);
  } catch(e) {
    log.warn(`  [fees] erro ao atualizar: ${e.message}`);
  }
}

// ─── NOTIFICATION PREFERENCES ─────────────────────────────────────────────
// Always reads from disk — so any changes made via the panel are reflected
// immediately, without restarting the monitor.
// config.json is small; a one-off synchronous read is negligible.
// Defaults: mempoolPending and txConfirmed = true by default;
//           everyBlock and priceChange = false by default.
function getNotifications() {
  return getCFG().notifications || {};
}

// Returns whether a notification type is enabled.
// Two-level logic for mempoolPending and txConfirmed:
//   - Global OFF  → nobody receives, regardless of per-wallet setting
//   - Global ON   → per-wallet wallet.notify[key] decides (falls back to true if not set)
// everyBlock and priceChange have no per-wallet override.
function notifEnabled(key, wallet) {
  const n = getNotifications();
  if (key === 'mempoolPending') {
    if (n.mempoolPending === false) return false;          // global off → skip everyone
    if (wallet?.notify && typeof wallet.notify.mempoolPending === 'boolean')
      return wallet.notify.mempoolPending;                 // per-wallet setting
    return true;
  }
  if (key === 'txConfirmed') {
    if (n.txConfirmed === false) return false;             // global off → skip everyone
    if (wallet?.notify && typeof wallet.notify.txConfirmed === 'boolean')
      return wallet.notify.txConfirmed;                    // per-wallet setting
    return true;
  }
  if (key === 'everyBlock')  return n.everyBlock  === true;
  if (key === 'priceChange') return n.priceChange === true;
  return true;
}

// Read a numeric value from notifications without depending on frozen CFG
function getNotifValue(key, fallback) {
  return getNotifications()[key] ?? fallback;
}

// ─── LOGGER ───────────────────────────────────────────────────────────────────
const ts = () => {
  const tz  = getCFG()?.timezone || 'UTC';
  const fmt = new Intl.DateTimeFormat([], {
    timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });
  const parts = Object.fromEntries(
    fmt.formatToParts(new Date()).filter(p => p.type !== 'literal').map(p => [p.type, p.value])
  );
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
};
const log = {
  info:  (...a) => console.log(`[${ts()}] ℹ️ `, ...a),
  ok:    (...a) => console.log(`[${ts()}] ✅ `, ...a),
  warn:  (...a) => console.warn(`[${ts()}] ⚠️ `, ...a),
  error: (...a) => console.error(`[${ts()}] ❌ `, ...a),
};

ensureConfig(); // ensure config.json exists and is complete

const sleep = ms => new Promise(r => setTimeout(r, ms));
const sats  = s  => (s / 1e8).toFixed(8);

// Format monetary value using the currency configured in general.currency
function fmtPrice(value) {
  const cur = getCFG().currency;
    const lang = getCFG().language;
  const dict = loadLang(lang) || loadLang('en-US') || {};
  const sym = cur === 'USD' ? '$' : cur === 'EUR' ? '€' : cur === 'GBP' ? '£' : cur === 'JPY' ? '¥' :
              cur === 'BRL' ? 'R$' : cur === 'CHF' ? 'CHF' : cur === 'CNY' ? '¥' : cur === 'INR' ? '₹' :
              cur === 'KRW' ? '₩' : cur === 'RUB' ? '₽' : cur === 'ARS' ? '$' : cur === 'ILS' ? '₪' : 
              cur === 'AED' ? 'د.إ' : cur === 'SAR' ? '﷼' : cur + ' ';
  return `${sym}${value.toLocaleString('en-US', { maximumFractionDigits: 2 })}`;
}

const now = () => {
  const cfg = getCFG();
  return new Date().toLocaleString(cfg.dateLocale, { timeZone: cfg.timezone });
};

function mempoolLink(txid) {
  const exp = getCFG().mempoolExplorer;
  if (!exp) return null;
  return `${exp.replace(/\/$/, '')}/tx/${txid}`;
}

function mempoolLinkLabel() {
  const exp = getCFG().mempoolExplorer;
  try { return new URL(exp).hostname; }
  catch { return exp; }
}

// ─── STATE ────────────────────────────────────────────────────────────────────
let state = {};

// In-memory cache of notifications already sent this session.
// Key: "txid|walletName" — allows the same txid to be notified
// from different perspectives (send from Wallet A, receive in Wallet B).
const notifiedTxids = new Set();

// Flag indicating whether the initial subscribeAll has completed.
// While false, ensureGap is not called (subscribeAll does the full scan).
let initialScanDone = false;

// Timestamp of the last block notification sent (module-level — survives reconnects)
let _lastBlockNotifAt = 0;

// Buffer of blocks accumulated during the interval
let _pendingBlocks = [];
let _blockFlushTimer = null;

// Reference to the active Electrum client — used by hot-reload
let _activeElectrum = null;

// Signals that the main loop should reconnect (server switch)
let _reconnectRequested = false;
let _reconnectTimer    = null;
// Prevents polling from triggering multiple reconnects while one is already in progress
let _serverChangePending = false;
// Module-level reference to the price timer — allows hotReloadConfig to cancel it
// and schedule an immediate fetch when currency changes.
let _priceTimerRef   = null;
let _priceRunning    = false;
let _lastNotifiedPrice = null;
let _appliedCfgRef   = null;
let _threshWarnLogged = false;

// ─── CONFIRMED NOTIFICATIONS BUFFER ──────────────────────────────────────
// Groups confirmed txs by (block, wallet) before sending
// a single consolidated message to Telegram.
//
// Key: "walletName:height"
// Value: { walletName, height, entries: [{ txid, classification }], timer }
const _confirmedBuffer = new Map();
const CONFIRMED_FLUSH_DELAY = 3000; // ms — waits 3s after last item before sending

async function flushConfirmedBuffer(key) {
  const buf = _confirmedBuffer.get(key);
  if (!buf || !buf.entries.length) { _confirmedBuffer.delete(key); return; }
  _confirmedBuffer.delete(key);

  const { walletName, height, entries } = buf;

  // ── Single tx → individual message as normal ────────────────────────────
  if (entries.length === 1) {
    const { txid, classification } = entries[0];
    const msg = buildTelegramMsg(classification, txid, height, false);
    if (msg) await sendNotification(msg);
    return;
  }

  // ── Multiple txs → consolidated message ─────────────────────────────────
  const _wallet = wallets.find(w => w.name === walletName);
  if (notifEnabled('txConfirmed', _wallet)) {
    const totalReceived = entries
      .filter(e => e.classification.type === 'received')
      .reduce((s, e) => s + (e.classification.valueSat || 0), 0);
    const totalSent = entries
      .filter(e => e.classification.type === 'sent' || e.classification.type === 'sent_with_change')
      .reduce((s, e) => s + (e.classification.sentSats || 0), 0);

    const lines = entries.map(e => {
      const c = e.classification;
      if (c.type === 'received')         return t('multi_tx_line_received',      { value: sats(c.valueSat) });
      if (c.type === 'sent')             return t('multi_tx_line_sent',          { value: sats(c.sentSats) });
      if (c.type === 'sent_with_change') return t('multi_tx_line_sent_change',   { value: sats(c.sentSats) });
      if (c.type === 'consolidation')    return t('multi_tx_line_consolidation', { value: sats(c.outputSats) });
      return `  • ${c.type}`;
    });

    const txidList = entries.map(e => `  🔗 <code>${e.txid}</code>`).join('\n');

    let summary = '';
    if (totalReceived > 0) summary += t('multi_tx_total_received', { value: sats(totalReceived) });
    if (totalSent > 0)     summary += t('multi_tx_total_sent',     { value: sats(totalSent) });

    const msg = t('multi_tx_confirmed', {
      count:  entries.length,
      wallet: walletName,
      height,
      summary,
      lines:  lines.join('\n'),
      txids:  txidList,
      time:   now(),
    });

    await sendNotification(msg);
  }

}

function loadState() {
  // Load the persisted state from the previous session.
  // subscribeAll compares the statusHash returned by the Electrum Server with the saved one:
  // if equal, history did not change offline and getHistory/getBalance are skipped.
  // If the file does not exist or is corrupted, start from scratch.
  try {
    const raw = fs.readFileSync(getCFG().stateFile, 'utf8');
    state = JSON.parse(raw);
    const count = Object.values(state).reduce((n, w) => {
      if (typeof w !== 'object') return n;
      return n + Object.values(w).reduce((m, l) => m + (typeof l === 'object' ? Object.keys(l).length : 0), 0);
    }, 0);
    log.info(`State loaded — ${count} known addresses (smart boot active)`);
  } catch {
    state = {};
    log.info('State not found — full scan on boot');
  }
}

function saveState() {
  try {
    // Rebuild state sorting addresses by BIP44 index
    const sorted = {};
    for (const walletName of Object.keys(state).sort()) {
      sorted[walletName] = {};
      for (const label of ['externo', 'change']) {
        const labelData = state[walletName]?.[label];
        if (!labelData) continue;
        // Sort addresses by index registered in addrMap
        const entries = Object.entries(labelData).sort(([addrA], [addrB]) => {
          const idxA = addrMap.get(addrA + '|' + walletName)?.index ?? 0;
          const idxB = addrMap.get(addrB + '|' + walletName)?.index ?? 0;
          return idxA - idxB;
        });
        if (entries.length) {
          sorted[walletName][label] = Object.fromEntries(entries);
        }
      }
      if (!Object.keys(sorted[walletName]).length) delete sorted[walletName];
    }
    // Persist the active gapLimit with state to detect offline changes
    sorted._meta = { gapLimit: getCFG().gapLimit };
    fs.writeFileSync(getCFG().stateFile, JSON.stringify(sorted, null, 2));
  } catch(e) { log.error('saveState:', e.message); }
}

// Reconcile gapLimit offline: if gapLimit was reduced while the script
// was offline, purge from state and wallet.addresses the empty addresses
// beyond the new cutoff — exactly as rebalanceGap would do live.
// Called after loadState() and loadWallets(), before connecting to the Electrum Server.
function reconcileGapOnBoot() {
  const currentGap = getCFG().gapLimit;
  const savedGap   = state._meta?.gapLimit ?? currentGap;
  delete state._meta; // remove metadata from in-memory state (not address data)

  if (currentGap >= savedGap) {
    // Increase or equal: subscribeAll will naturally derive the new addresses
    if (currentGap > savedGap)
      log.info(`[boot] gapLimit increased offline (${savedGap} → ${currentGap}) — subscribeAll will derive new addresses`);
    return;
  }

  log.info(`[boot] gapLimit reduced offline (${savedGap} → ${currentGap}) — purging excess addresses from state`);
  let totalPurged = 0;

  for (const wallet of wallets) {
    if (!wallet.descriptor || wallet.descriptor.startsWith('addr(')) continue;

    for (const chain of [0, 1]) {
      const label    = chain === 0 ? 'ext' : 'chg';
      const stLabel  = chain === 0 ? 'externo' : 'change';
      const addrs    = (wallet.addresses || []).filter(a => a.chain === chain)
                         .sort((a, b) => a.index - b.index);
      if (!addrs.length) continue;

      // Index of last address with history
      let lastUsed = -1;
      for (const a of addrs) {
        const st = state[wallet.name]?.[stLabel]?.[a.address];
        if (!st) continue;
        if ((st.balanceSat || 0) > 0 || (st.txids?.length || 0) > 0 || (st.mempoolTxids?.length || 0) > 0)
          lastUsed = a.index;
      }

      const startIdx = wallet.startIndex ?? 0;
      const base     = lastUsed >= 0 ? lastUsed : startIdx - 1;
      const cutoff   = base + currentGap;
      let purged     = 0;

      for (const a of [...addrs]) {
        if (a.index <= cutoff) continue;
        const st = state[wallet.name]?.[stLabel]?.[a.address];
        const hasHistory = st && ((st.balanceSat || 0) > 0 || (st.txids?.length || 0) > 0 || (st.mempoolTxids?.length || 0) > 0);
        if (hasHistory) continue; // never remove an address with history

        // Remove de addrMap e shMap
        addrMap.delete(a.address + '|' + wallet.name);
        const shList = shMap.get(a.scriptHash);
        if (shList) {
          const filtered = shList.filter(e => e.wallet.name !== wallet.name || e.address !== a.address);
          if (filtered.length) shMap.set(a.scriptHash, filtered);
          else shMap.delete(a.scriptHash);
        }
        // Remove de wallet.addresses
        const wIdx = wallet.addresses.indexOf(a);
        if (wIdx !== -1) wallet.addresses.splice(wIdx, 1);
        // Remove from in-memory state
        if (state[wallet.name]?.[stLabel])
          delete state[wallet.name][stLabel][a.address];
        purged++;
      }

      if (purged > 0)
        log.info(`  [boot] ${wallet.name} [${label}]: ${purged} addresses purged (cutoff idx ${cutoff})`);
    }
  }

  if (totalPurged > 0 || true) saveState(); // rewrite state.json with new gapLimit
}

function getAddrState(addr, walletName) {
  const info = addrMap.get(addr + '|' + walletName);
  if (!info) return { balanceSat: null, txids: [], mempoolTxids: [], statusHash: null };
  const label = info.chain === 0 ? 'externo' : 'change';
  return state[walletName]?.[label]?.[addr] || { balanceSat: null, txids: [], mempoolTxids: [], statusHash: null };
}

function setAddrState(addr, data, walletName) {
  const info = addrMap.get(addr + '|' + walletName);
  if (!info) return;
  const label = info.chain === 0 ? 'externo' : 'change';
  if (!state[walletName])        state[walletName] = {};
  if (!state[walletName][label]) state[walletName][label] = {};
  const prev = getAddrState(addr, walletName);
  state[walletName][label][addr] = { addressIndex: info.index, ...prev, ...data, lastUpdate: Date.now() };
  saveState();
}

// ─── WALLETS & DERIVATION ──────────────────────────────────────────────────────
let wallets = [];
const addrMap = new Map(); // "address|walletName" → { wallet, chain, index, scriptHash, scriptHex }
const shMap   = new Map(); // scriptHash           → [{ address, wallet, chain, index }]

function walletHrp(w) {
  if (w.network === 'signet' || w.network === 'testnet') return 'tb';
  if (w.network === 'regtest') return 'bcrt';
  return 'bc';
}

function deriveOne(descriptor, hrp, index, chain) {
  try {
    const r = analyzeDescriptor(descriptor, { hrp, deriveSpec: [{ index, chain }] });
    const a = r.addresses[0];
    if (!a || !a.scriptHex) return null;
    return { ...a, scriptHash: scriptToScriptHash(a.scriptHex) };
  } catch { return null; }
}

function registerAddress(entry, wallet, chain, index) {
  const key = entry.address + '|' + wallet.name;
  addrMap.set(key, { wallet, chain, index, scriptHash: entry.scriptHash, scriptHex: entry.scriptHex });
  const list = shMap.get(entry.scriptHash) || [];
  if (!list.some(e => e.address === entry.address && e.wallet.name === wallet.name)) {
    list.push({ address: entry.address, wallet, chain, index });
  }
  shMap.set(entry.scriptHash, list);
}

function ensureGap(wallet, chain, usedIndex, electrum) {
  const hrp    = walletHrp(wallet);
  const cfg    = getCFG();
  const needed = usedIndex + cfg.gapLimit;
  const desc   = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;

  // Highest index already derived for this chain
  const existing = (wallet.addresses || []).filter(a => a.chain === chain);
  const lastIdx  = existing.length ? Math.max(...existing.map(a => a.index)) : -1;
  if (lastIdx >= needed) return [];

  const newEntries = [];
  for (let i = lastIdx + 1; i <= Math.min(needed, cfg.maxIndex); i++) {
    // Avoid deriving already-present index (protection against concurrent calls)
    if (wallet.addresses.some(a => a.chain === chain && a.index === i)) continue;
    const entry = deriveOne(desc, hrp, i, chain);
    if (!entry) continue;
    wallet.addresses.push({ ...entry, chain, index: i });
    registerAddress(entry, wallet, chain, i);
    newEntries.push(entry);
  }

  if (newEntries.length > 0) {
    const label = chain === 0 ? 'externos' : 'change';
    log.info(`  Gap [${wallet.name}]: +${newEntries.length} ${label} (idx ${lastIdx + 1}..${Math.min(needed, cfg.maxIndex)})`);
    if (electrum?.connected) {
      for (const e of newEntries) {
        electrum.subscribe(e.scriptHash).then(async status => {
          if (status) {
            await processChange(electrum, e.scriptHash, status).catch(() => {});
          } else {
            setAddrState(e.address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: null }, wallet.name);
          }
        }).catch(err => log.warn(`  subscribe ${e.address.slice(0,16)}…: ${err.message}`));
      }
    }
  }
  return newEntries;
}

function loadWallets() {
  try {
    if (fs.existsSync(getCFG().walletsFile)) {
      wallets = JSON.parse(fs.readFileSync(getCFG().walletsFile, 'utf8'));
    } else {
      fs.writeFileSync(getCFG().walletsFile, JSON.stringify([], null, 2));
      log.info('wallets.json created — add wallets via the panel');
      wallets = [];
    }
  } catch { wallets = []; }

  if (!wallets.length) {
    log.warn('No wallets configured — add descriptors via the panel');
  }

  addrMap.clear(); shMap.clear();

  for (const wallet of wallets) {
    if (!wallet.descriptor) continue;
    wallet.addresses = wallet.addresses || [];

    const hrp = walletHrp(wallet);
    const startIdx = wallet.startIndex ?? 0;

    // Derive and register only already-known addresses (from previous boots).
    // subscribeAll will derive more as needed by querying the Electrum Server.
    const isSingleAddress = wallet.descriptor.startsWith('addr(');

    const chains = isSingleAddress ? [0] : [0, 1];

    for (const chain of chains) {
      const desc = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;

      // Ensure each entry has chain and index filled in
      for (const entry of wallet.addresses.filter(a => a.chain === chain)) {
        const sh = entry.scriptHash || (entry.scriptHex ? scriptToScriptHash(entry.scriptHex) : null);
        if (sh) registerAddress({ ...entry, scriptHash: sh }, wallet, chain, entry.index ?? 0);
      }

      // Derive at least the first gapLimit addresses as a starting point.
      // For addr() there is no real derivation — derive only index 0 and stop.
      const existing = wallet.addresses.filter(a => a.chain === chain);
      const lastIdx  = existing.length ? Math.max(...existing.map(a => a.index ?? 0)) : startIdx - 1;
      const minDerive = isSingleAddress ? startIdx : Math.max(startIdx + getCFG().gapLimit - 1, lastIdx);
      for (let i = startIdx; i <= minDerive; i++) {
        if (wallet.addresses.some(a => a.chain === chain && a.index === i)) continue;
        const entry = deriveOne(desc, hrp, i, chain);
        if (entry) {
          wallet.addresses.push({ ...entry, chain, index: i });
          registerAddress(entry, wallet, chain, i);
        }
        if (isSingleAddress) break;
      }
    }

    const ext = wallet.addresses.filter(a => a.chain === 0).length;
    const chg = wallet.addresses.filter(a => a.chain === 1).length;
    log.info(`  ${wallet.name}: ${ext} ext, ${chg} chg pre-derived`);
  }
}


// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
function sendTelegram(text) {
  const { enabled, token, chatId } = getCFG().telegram;
  if (!enabled || !token || !chatId) return Promise.resolve();
  const body = JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' });
  return new Promise(resolve => {
    const req = https.request({
      hostname: 'api.telegram.org',
      path:     `/bot${token}/sendMessage`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', () => resolve());
    req.write(body); req.end();
  });
}

function sendNtfy(text) {
  const { enabled, url, token } = getCFG().ntfy || {};
  if (!enabled || !url) return Promise.resolve();
  // Convert Telegram HTML tags to ntfy Markdown
  const clean = text
    .replace(/<b>(.*?)<\/b>/gi,                        '**$1**')   // negrito
    .replace(/<i>(.*?)<\/i>/gi,                        '*$1*')     // italic
    .replace(/<code>(.*?)<\/code>/gi,                  '`$1`')     // inline code
    .replace(/<a\b[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)') // link
    .replace(/<[^>]+>/g, '');                                       // tags restantes
  const body  = Buffer.from(clean, 'utf8');
  const u     = new URL(url);
  const lib   = u.protocol === 'https:' ? require('https') : require('http');
  const headers = {
    'Content-Type':   'text/plain',
    'Content-Length': body.length,
    'Markdown':       'yes',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return new Promise(resolve => {
    const req = lib.request({
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname,
      method:   'POST',
      headers,
    }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', () => resolve());
    req.write(body); req.end();
  });
}

function sendNotification(text) {
  return Promise.all([sendTelegram(text), sendNtfy(text)]);
}

// ─── TRANSACTION CLASSIFICATION ─────────────────────────────────────────────
//
// Analyzes a complete tx and determines:
//   - if any vin belongs to our state → outgoing/consolidation
//   - if no vin belongs to our state → external receive
//
// Types:
//   'received'         — external origin, value entered one of our addresses
//   'sent'             — outgoing without change to our addresses
//   'sent_with_change' — outgoing with change returning to our address
//   'consolidation'    — all output goes to our own addresses
//
// electrum is optional: if provided, used as fallback to fetch prevouts
// when the server does not include them in verbose tx (Electrum Server < 1.9).

async function classifyTx(txData, walletName, network, electrum) {
  const vins  = txData.vin  || [];
  const vouts = txData.vout || [];

  // ── Map each vout to its scriptHash ──────────────────────────────────────
  const voutScriptHashes = vouts.map(out => {
    const hex = out.scriptPubKey?.hex || '';
    return hex ? scriptHexToScriptHash(hex) : null;
  });

  // ── Detect our inputs ──────────────────────────────────────────────────
  // Strategy 1: vin.prevout.scriptPubKey.hex (Electrum Server >= 1.9, verbose=true)
  // Strategy 2: fallback — fetch the previous tx and get vout[vin.vout]
  let myInputSats = 0;
  const inputAddrs = new Set();

  for (const vin of vins) {
    if (vin.coinbase) continue; // coinbase tx has no real prevout

    let prevScript = vin.prevout?.scriptPubKey?.hex || '';
    let prevValue  = vin.prevout?.value ?? null;

    // Fallback: fetch the input tx to get scriptPubKey and/or value when
    // the Electrum Server does not include full prevout (common on Signet/Testnet mempool)
    if ((!prevScript || prevValue === null) && electrum && vin.txid) {
      try {
        const prevTx  = await electrum.getTransaction(vin.txid);
        const prevOut = (prevTx.vout || [])[vin.vout];
        if (!prevScript)       prevScript = prevOut?.scriptPubKey?.hex || '';
        if (prevValue === null) prevValue  = prevOut?.value ?? null;
      } catch { /* ignora falha de lookup — assume externo */ }
    }

    if (!prevScript) continue;

    const prevSh    = scriptHexToScriptHash(prevScript);
    // Only count as our input if it belongs to the SAME wallet being analyzed
    const prevEntry = (shMap.get(prevSh) || []).find(e => e.wallet.name === walletName);
    const addr      = prevEntry?.address;
    if (addr && addrMap.has(addr + '|' + walletName)) {
      const val = prevValue ?? 0;
      myInputSats += Math.round(val * 1e8);
      inputAddrs.add(addr);
    }
  }

  const isOutgoing = inputAddrs.size > 0;

  // ── Classify vouts ───────────────────────────────────────────────────────
  let myOutputSats    = 0;
  let extOutputSats   = 0;
  const changeOutputs = []; // vouts returning to our own addresses
  const extOutputs    = []; // vouts going to external addresses

  for (let i = 0; i < vouts.length; i++) {
    const out    = vouts[i];
    const sh      = voutScriptHashes[i];
    const valSat  = Math.round((out.value || 0) * 1e8);

    // Only consider "our address" if it belongs to the SAME wallet being
    // analyzed — avoids classifying a transfer between monitored
    // wallets as an internal consolidation.
    const shEntries = sh ? (shMap.get(sh) || []) : [];
    const shEntry   = shEntries.find(e => e.wallet.name === walletName);
    const addr      = shEntry?.address;

    if (addr && addrMap.has(addr + '|' + walletName)) {
      myOutputSats += valSat;
      changeOutputs.push({ address: addr, valueSat: valSat });
    } else {
      extOutputSats += valSat;
      const extAddr = out.scriptPubKey?.address || out.scriptPubKey?.addresses?.[0] || '?';
      extOutputs.push({ address: extAddr, valueSat: valSat });
    }
  }

  // ── PURE RECEIVE ────────────────────────────────────────────────────────
  if (!isOutgoing) {
    if (!myOutputSats) return null; // no our vout — should not happen
    return {
      type:         'received',
      walletName,
      network,
      valueSat:     myOutputSats,
      destinations: changeOutputs,
    };
  }

  // ── OUTGOING ───────────────────────────────────────────────────────────────────
  const hasExternalOutput = extOutputs.length > 0;
  const hasChangeOutput   = changeOutputs.length > 0;

  if (!hasExternalOutput) {
    // All output went to our own addresses → internal consolidation
    return {
      type:         'consolidation',
      walletName,
      network,
      inputSats:    myInputSats,
      outputSats:   myOutputSats,
      destinations: changeOutputs,
      inputAddrs:   [...inputAddrs],
    };
  }

  if (hasChangeOutput) {
    // Sent outward with change returning
    return {
      type:          'sent_with_change',
      walletName,
      network,
      sentSats:      extOutputSats,
      changeSats:    myOutputSats,
      feeSats:       Math.max(0, myInputSats - extOutputSats - myOutputSats),
      destinations:  extOutputs,
      changeOutputs,
      inputAddrs:    [...inputAddrs],
    };
  }

  // Sent everything outward, no change
  return {
    type:         'sent',
    walletName,
    network,
    sentSats:     extOutputSats,
    feeSats:      Math.max(0, myInputSats - extOutputSats),
    destinations: extOutputs,
    inputAddrs:   [...inputAddrs],
  };
}

// ─── TELEGRAM MESSAGE BUILDER ─────────────────────────────────────────────────
function buildTelegramMsg(classification, txid, height, isPending) {
  const { type, walletName } = classification;
  const _url   = mempoolLink(txid);
  const link   = _url ? `\n<a href="${_url}">${t('tx_view_on', { explorer: mempoolLinkLabel() })}</a>` : '';
  const status = isPending ? t('tx_status_pending') : t('tx_status_confirmed', { height });
  const time   = now();

  const destLine = d => `  📍 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`;
  const sentLine = d => `  📤 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`;
  const chgLine  = d => `  🔄 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`;

  if (type === 'received') {
    return t('tx_received', {
      wallet: walletName,
      total:  sats(classification.valueSat),
      dests:  classification.destinations.map(destLine).join('\n'),
      txid, status, time, link,
    });
  }

  if (type === 'sent') {
    return t('tx_sent', {
      wallet: walletName,
      sent:   sats(classification.sentSats),
      fee:    sats(classification.feeSats),
      dests:  classification.destinations.map(sentLine).join('\n'),
      txid, status, time, link,
    });
  }

  if (type === 'sent_with_change') {
    return t('tx_sent_change', {
      wallet:  walletName,
      sent:    sats(classification.sentSats),
      change:  sats(classification.changeSats),
      fee:     sats(classification.feeSats),
      dests:   classification.destinations.map(sentLine).join('\n'),
      changes: classification.changeOutputs.map(chgLine).join('\n'),
      txid, status, time, link,
    });
  }

  if (type === 'consolidation') {
    return t('tx_consolidation', {
      wallet: walletName,
      output: sats(classification.outputSats),
      dests:  classification.destinations.map(d => `  🔀 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`).join('\n'),
      txid, status, time, link,
    });
  }

  return null;
}

function msgStartup(addrCount, gapLimit) {
  const _e = getCFG().electrum;
  return t('startup', {
    host:      _e.host,
    port:      _e.port,
    addrCount,
    gapLimit,
    time:      now(),
  });
}

// ─── ELECTRUM CLIENT ─────────────────────────────────────────────────────────
class ElectrumClient {
  constructor() {
    this.socket  = null;
    this.connected = false;
    this.buffer  = '';
    this.pending = new Map(); // id → { resolve, reject, timer }
    this.subs    = new Map(); // method → handler
    this.msgId   = 1;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const { host, port, tls: useTLS } = getCFG().electrum;
      if (!host) { reject(new Error('host not configured — set electrum.host in config.json or via the panel')); return; }
      log.info(`  [connect] ${host}:${port} TLS=${useTLS}`);

      // Ensure resolve/reject are only called once
      let settled = false;
      const _resolve = (v) => { if (!settled) { settled = true; resolve(v); } };
      const _reject  = (e) => { if (!settled) { settled = true; reject(e);  } };

      this.socket = useTLS
        ? tls.connect({ host, port, rejectUnauthorized: false }, () => this._onConnect(_resolve))
        : net.connect({ host, port }, () => this._onConnect(_resolve));

      this.socket.setEncoding('utf8');
      this.socket.setTimeout(15000);
      this.socket.on('data',    chunk => this._onData(chunk));
      this.socket.on('error',   err   => { this.connected = false; writeRuntime({ electrum: { connected: false, error: err.message, since: Date.now() } }); this._flushPending(err); _reject(err); });
      this.socket.on('close',   ()    => { this.connected = false; log.warn('Electrum: connection closed'); this._flushPending(new Error('connection closed')); _reject(new Error('connection closed')); });
      this.socket.on('timeout', ()    => { this.socket.destroy(); _reject(new Error('connection timeout')); });
    });
  }

  // Rejeita imediatamente todas as Promises de call() em andamento.
  // Called on socket close to avoid waiting 20s per pending request.
  _flushPending(err) {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  _onConnect(resolve) {
    this.connected = true;
    this.socket.setTimeout(0);
    try { this.socket.setKeepAlive(true, 10000); } catch {}
    this._resetInactivityTimer();
    const _ec = getCFG().electrum;
    log.ok(`Electrum Server → ${_ec.host}:${_ec.port}${_ec.tls ? ' (TLS)' : ' (TCP)'}`);
    writeRuntime({ electrum: { connected: true, host: _ec.host, port: _ec.port, tls: _ec.tls, since: Date.now() } });
    resolve();
  }

  _resetInactivityTimer() {
    clearTimeout(this._inactivityTimer);
    this._inactivityTimer = setTimeout(() => {
      log.warn('Electrum: 90s without data — forcing reconnect');
      this.connected = false;
      writeRuntime({ electrum: { connected: false, error: 'inactivity timeout', since: Date.now() } });
      this.socket?.destroy();
    }, 90000);
  }

  _onData(chunk) {
    this._resetInactivityTimer?.();
    this.buffer += chunk;
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }

      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (p) {
          clearTimeout(p.timer);
          this.pending.delete(msg.id);
          msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
        }
      } else if (msg.method) {
        const h = this.subs.get(msg.method);
        if (h) { try { h(msg.params); } catch(e) { log.error('sub handler:', e.message); } }
      }
    }
  }

  call(method, params = [], timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      if (!this.connected) return reject(new Error('not connected'));
      const id    = this.msgId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.write(JSON.stringify({ id, method, params }) + '\n');
    });
  }

  on(method, handler) { this.subs.set(method, handler); }

  subscribe(scriptHash)  { return this.call('blockchain.scripthash.subscribe', [scriptHash]); }
  getHistory(scriptHash) { return this.call('blockchain.scripthash.get_history', [scriptHash]); }
  getBalance(scriptHash) { return this.call('blockchain.scripthash.get_balance', [scriptHash]); }
  getTransaction(txid)   { return this.call('blockchain.transaction.get', [txid, true]); }
  ping()                 { return this.call('server.ping', [], 10000); }
  getFeeHistogram()      { return this.call('mempool.get_fee_histogram', [], 10000); }
  disconnect()           { this.connected = false; clearTimeout(this._inactivityTimer); this.socket?.destroy(); }
}

// ─── UTILITY: scriptHex → scriptHash (reversed SHA256) ─────────────────────
function scriptHexToScriptHash(scriptHex) {
  return createHash('sha256')
    .update(Buffer.from(scriptHex, 'hex'))
    .digest()
    .reverse()
    .toString('hex');
}

// ─── COMPUTE VALUE RECEIVED IN A TX (vouts belonging to our scriptHash) ─
function calcReceivedValue(txData, scriptHash) {
  let totalSats = 0;
  for (const out of (txData.vout || [])) {
    const outScript = out.scriptPubKey?.hex || '';
    if (!outScript) continue;
    if (scriptHexToScriptHash(outScript) === scriptHash)
      totalSats += Math.round((out.value || 0) * 1e8);
  }
  return totalSats;
}

// ─── PROCESS SCRIPTHASH CHANGE ──────────────────────────────────────────
async function processChange(electrum, scriptHash, newStatusHash) {
  const entries = shMap.get(scriptHash);
  if (!entries || !entries.length) return;

  // Fetch history once — it is the same for all wallets
  const history = await electrum.getHistory(scriptHash).catch(() => []);
  const confirmedTxids = history.filter(h => h.height > 0).map(h => h.tx_hash);
  const mempoolTxids   = history.filter(h => h.height <= 0).map(h => h.tx_hash);

  // Fetch balance once
  const balance  = history.length
    ? await electrum.getBalance(scriptHash).catch(() => ({ confirmed: 0, unconfirmed: 0 }))
    : { confirmed: 0, unconfirmed: 0 };
  const confirmedSat  = balance.confirmed  || 0;
  const unconfirmedSat= balance.unconfirmed|| 0;
  const totalSat = confirmedSat + unconfirmedSat;

  // Process each wallet monitoring this scriptHash independently
  for (const { address, wallet, chain, index } of entries) {
    const network = wallet.network || 'mainnet';
    const prev    = getAddrState(address, wallet.name);

    // Skip if status unchanged and already initialized
    if (prev.statusHash === newStatusHash && prev.balanceSat !== null) continue;

    if (!history.length) {
      setAddrState(address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: newStatusHash }, wallet.name);
      continue;
    }

    const prevConfirmed = prev.txids        || [];
    const prevMempool   = prev.mempoolTxids || [];

    // ── Silent sync ──
    const isFirstSync  = prev.balanceSat === null;
    const isCatchingUp = !initialScanDone;
    if (isFirstSync || isCatchingUp) {
      setAddrState(address, {
        balanceSat:     confirmedSat,
        unconfirmedSat: unconfirmedSat,
        txids:          confirmedTxids,
        mempoolTxids:   mempoolTxids,
        statusHash:     newStatusHash,
      }, wallet.name);
      if (isFirstSync)
        log.info(`  Initial sync: ${address.slice(0,20)}… ${confirmedTxids.length} txs, balance ${sats(confirmedSat)} BTC (+${sats(unconfirmedSat)} mempool)`);
      else
        log.info(`  Catch-up: ${address.slice(0,20)}… ${confirmedTxids.length} txs (offline gap, no notification)`);

      // ── txhistory catch-up ─────────────────────────────────────────────
      const allTxids = [...confirmedTxids, ...mempoolTxids];
      for (const txid of allTxids) {
        const he = history.find(h => h.tx_hash === txid);
        const isNowConfirmed = he?.height > 0;

        if (txHistoryHas(wallet.name, txid)) {
          if (isNowConfirmed) {
            const cur = readTxHistory();
            const rec = cur[wallet.name]?.txids?.[txid];
            if (rec && rec.mempool) {
              rec.mempool = false;
              rec.height  = he.height;
              if (he.time) rec.ts = he.time * 1000;
              writeTxHistory(cur);
              log.info(`  [txhistory] ${txid.slice(0,16)}… promoted mempool→block #${he.height}`);
            }
          }
          continue;
        }

        try {
          const txData = await electrum.getTransaction(txid).catch(() => null);
          if (!txData) continue;
          const cl = await classifyTx(txData, wallet.name, network, electrum);
          if (!cl) continue;
          const ht = isNowConfirmed ? he.height : null;
          appendTxHistory(cl, txid, ht, !isNowConfirmed, he);
        } catch(e) { log.warn(`  [txhistory catch-up] ${txid.slice(0,16)}…: ${e.message}`); }
      }

      if (initialScanDone) ensureGap(wallet, chain, index, electrum);
      continue;
    }

    // ── Subsequent sync — only notify real changes ──
    let hasActivity = false;

    // ── Mempool: one message per tx (no grouping) ─────────────────────
    async function notifyMempool(txid) {
      const notifKey = `${txid}|${wallet.name}`;
      if (notifiedTxids.has(notifKey)) return;
      notifiedTxids.add(notifKey);
      let txData;
      try { txData = await electrum.getTransaction(txid); }
      catch(e) { log.warn(`  transaction.get ${txid.slice(0,16)}…: ${e.message}`); return; }
      const classification = await classifyTx(txData, wallet.name, network, electrum);
      if (!classification) { log.warn(`  classifyTx: no matching vout in ${txid.slice(0,16)}…`); return; }

      // Record in history (mempool=true)
      const he = history.find(h => h.tx_hash === txid);
      appendTxHistory(classification, txid, null, true, he);

      if (!notifEnabled('mempoolPending', wallet)) {
        log.info(`  [filter] mempool tx skipped (notification disabled): ${txid.slice(0,16)}… [${wallet.name}]`);
        return;
      }
      const msg = buildTelegramMsg(classification, txid, null, true);
      if (!msg) return;
      log.info(`📥 [${classification.type}] ${address.slice(0,20)}… ${txid.slice(0,16)}…`);
      await sendNotification(msg);
    }

    // ── Confirmed: buffer by (block, wallet) ─────────────────
    async function bufferConfirmed(txid, height) {
      // Confirmation-specific key — prevents two addresses of the same
      // wallet (e.g. output + change) from processing the same txid twice
      const confirmedKey = `confirmed:${txid}|${wallet.name}`;
      if (notifiedTxids.has(confirmedKey)) return;
      notifiedTxids.add(confirmedKey);
      let txData;
      try { txData = await electrum.getTransaction(txid); }
      catch(e) { log.warn(`  transaction.get ${txid.slice(0,16)}…: ${e.message}`); return; }
      const classification = await classifyTx(txData, wallet.name, network, electrum);
      if (!classification) { log.warn(`  classifyTx: no matching vout in ${txid.slice(0,16)}…`); return; }

      // Record/update in history (confirmed)
      const he = history.find(h => h.tx_hash === txid);
      appendTxHistory(classification, txid, height, false, he);

      if (!notifEnabled('txConfirmed', wallet)) {
        log.info(`  [filter] confirmed tx skipped (notification disabled): ${txid.slice(0,16)}… [${wallet.name}]`);
        return;
      }
      log.info(`✅ [${classification.type}] ${address.slice(0,20)}… ${txid.slice(0,16)}… → buffer bloco #${height}`);

      const key = `${wallet.name}:${height}`;
      const buf = _confirmedBuffer.get(key) || { walletName: wallet.name, height, entries: [], timer: null };
      buf.entries.push({ txid, classification });

      // Restart debounce — sends 3s after the last item added
      clearTimeout(buf.timer);
      buf.timer = setTimeout(() => flushConfirmedBuffer(key), CONFIRMED_FLUSH_DELAY);
      _confirmedBuffer.set(key, buf);
    }

    for (const txid of mempoolTxids) {
      if (prevMempool.includes(txid) || prevConfirmed.includes(txid)) continue;
      hasActivity = true;
      await notifyMempool(txid);
    }

    // ── Detect dropped/RBF live ──────────────────────────────────────────
    // Txids that were in the previous mempool but disappeared without confirming
    for (const txid of prevMempool) {
      if (mempoolTxids.includes(txid) || confirmedTxids.includes(txid)) continue;
      // Disappeared from mempool without confirming → dropped or replaced by RBF
      const cur = readTxHistory();
      const rec = cur[wallet.name]?.txids?.[txid];
      if (rec && rec.mempool) {
        rec.mempool   = false;
        rec.dropped   = true;
        rec.droppedAt = Date.now();
        writeTxHistory(cur);
        log.warn(`  [RBF/drop] ${txid.slice(0,16)}… dropped from mempool without confirming (${wallet.name})`);
        if (notifEnabled('mempoolPending', wallet)) {
          await sendNotification(
            t('mempool_dropped', { wallet: wallet.name, txid, time: now() })
          ).catch(() => {});
        }
      }
    }

    for (const txid of confirmedTxids) {
      if (prevConfirmed.includes(txid)) continue;
      hasActivity = true;
      const histEntry = history.find(h => h.tx_hash === txid);
      const height    = histEntry ? histEntry.height : '?';
      await bufferConfirmed(txid, height);
    }

    setAddrState(address, {
      balanceSat:     confirmedSat,
      unconfirmedSat: unconfirmedSat,
      txids:          confirmedTxids,
      mempoolTxids:   mempoolTxids,
      statusHash:     newStatusHash,
    }, wallet.name);

    if (hasActivity || history.length > 0) {
      ensureGap(wallet, chain, index, electrum);
    }
  }
}

// ─── SUBSCRIBE ALL ADDRESSES ─────────────────────────────────────────────
// Special error used to abort subscribeAll in a controlled way.
// The main loop catch recognizes this type and treats it as an intentional reconnect.
class AbortScanError extends Error {
  constructor() { super('scan interrupted — server switch'); this.isAbort = true; }
}

async function subscribeAll(electrum) {
  // Check whether to abort — throws AbortScanError if _reconnectRequested is active
  // or if the socket was destroyed (electrum.connected = false after hot-reload).
  function checkAbort() {
    if (_reconnectRequested || !electrum.connected) throw new AbortScanError();
  }

  electrum.on('blockchain.scripthash.subscribe', async ([sh, statusHash]) => {
    try { await processChange(electrum, sh, statusHash); }
    catch(e) { log.error('processChange:', e.message); }
  });

  electrum.on('blockchain.headers.subscribe', async ([header]) => {
    const height = header.height;
    log.info(`🧱 New block #${height}`);

    const everyBlockOn = notifEnabled('everyBlock');
    log.info(`  [block] everyBlock=${everyBlockOn}`);
    if (!everyBlockOn) return;

    const intervalMin = getNotifValue('blockIntervalMin', 0);

    // Acumula o bloco no buffer
    _pendingBlocks.push(height);

    if (intervalMin === 0) {
      // No interval — send immediately one by one
      _pendingBlocks = [];
      log.info(`  [block] sending notification for block #${height}`);
      await sendNotification(t('block_single', { height, time: now() }))
        .catch(e => log.warn(`  [block] send error: ${e.message}`));
      return;
    }

    // With interval — accumulate and flush at end of period
    const now_ms  = Date.now();
    const elapsed = now_ms - _lastBlockNotifAt;
    const needed  = intervalMin * 60 * 1000;

    if (elapsed >= needed) {
      // Interval expired — immediate flush
      clearTimeout(_blockFlushTimer);
      _blockFlushTimer = null;
      const blocks = [..._pendingBlocks];
      _pendingBlocks = [];
      _lastBlockNotifAt = now_ms;
      await flushBlocks(blocks);
    } else if (!_blockFlushTimer) {
      // Schedule flush for when interval expires
      const remaining = needed - elapsed;
      log.info(`  [block] accumulating — flush in ${Math.round(remaining/1000)}s`);
      _blockFlushTimer = setTimeout(async () => {
        _blockFlushTimer = null;
        const blocks = [..._pendingBlocks];
        _pendingBlocks = [];
        _lastBlockNotifAt = Date.now();
        await flushBlocks(blocks);
      }, remaining);
    } else {
      log.info(`  [block] accumulating block #${height} (${_pendingBlocks.length} in buffer)`);
    }
  });

  async function flushBlocks(blocks) {
    if (!blocks.length) return;
    if (blocks.length === 1) {
      log.info(`  [block] sending notification for block #${blocks[0]}`);
      await sendNotification(t('block_single', { height: blocks[0], time: now() }))
        .catch(e => log.warn(`  [block] send error: ${e.message}`));
    } else {
      const list = blocks.map(h => `#${h}`).join(', ');
      log.info(`  [block] sending ${blocks.length} accumulated blocks: ${list}`);
      await sendNotification(t('block_multi', { count: blocks.length, list, time: now() }))
        .catch(e => log.warn(`  [block] send error: ${e.message}`));
    }
  }
  try {
    const tip = await electrum.call('blockchain.headers.subscribe', []);
    log.info(`Current block: #${tip.height || tip.block_height || '?'}`);
  } catch {}

  let totalOk = 0;
  initialScanDone = false; // reset for each connection cycle

  for (const wallet of wallets) {
    if (!wallet.descriptor) continue;
    const hrp      = walletHrp(wallet);
    const startIdx = wallet.startIndex ?? 0;

    const isSingleAddress = wallet.descriptor.startsWith('addr(');

    const chains = isSingleAddress ? [0] : [0, 1];

    for (const chain of chains) {

      const desc  = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;
      const label = chain === 0 ? 'ext' : 'chg';

      // BIP44 scan: advances sequentially, stops only when the Electrum Server
      // confirms gapLimit consecutive empty addresses.
      let consecutiveEmpty = 0;
      let i = startIdx;
      let lastUsed = startIdx - 1;

      while (consecutiveEmpty < getCFG().gapLimit && i <= getCFG().maxIndex) {
        checkAbort(); // ← abort immediately if server was switched

        // Derive the address if it does not exist yet
        let entry = wallet.addresses.find(a => a.chain === chain && a.index === i);
        if (!entry) {
          entry = deriveOne(desc, hrp, i, chain);
          if (!entry) { i++; consecutiveEmpty++; continue; }
          wallet.addresses.push({ ...entry, chain, index: i });
          registerAddress(entry, wallet, chain, i);
        } else if (!shMap.get(entry.scriptHash)?.some(e => e.wallet.name === wallet.name)) {
          registerAddress(entry, wallet, chain, i);
        }

        try {
          const statusHash = await electrum.subscribe(entry.scriptHash);

          // ── Smart boot: compare statusHash with the one saved in the previous session ──
          // hashUnchanged: statusHash equal to saved → history intact offline
          // knownEmpty:    statusHash null + balanceSat 0 → still empty
          // Both cases skip getHistory/getBalance.
          const prevState    = getAddrState(entry.address, wallet.name);
          const knownHash    = prevState.statusHash;
          const knownBalance = prevState.balanceSat;

          const hashUnchanged = statusHash !== null && statusHash === knownHash && knownBalance !== null;
          const knownEmpty    = statusHash === null  && knownBalance === 0;

          if (hashUnchanged || knownEmpty) {
            consecutiveEmpty = (knownBalance > 0 || (prevState.txids?.length || 0) > 0) ? 0 : consecutiveEmpty + 1;
            if (knownBalance > 0 || (prevState.txids?.length || 0) > 0) lastUsed = i;
            totalOk++;
            await sleep(getCFG().subscribeDelayMs);
            checkAbort(); // ← check after each sleep
            i++;
            if (isSingleAddress) break;
            continue;
          }

          if (statusHash) {
            consecutiveEmpty = 0;
            lastUsed = i;
            processChange(electrum, entry.scriptHash, statusHash).catch(e =>
              log.error(`processChange [${label}/${i}]:`, e.message)
            );
          } else {
            let hasHistory = false;
            try {
              const hist = await electrum.getHistory(entry.scriptHash);
              hasHistory = hist && hist.length > 0;
            } catch { /* assume vazio em caso de erro */ }

            if (hasHistory) {
              consecutiveEmpty = 0;
              lastUsed = i;
              processChange(electrum, entry.scriptHash, null).catch(e =>
                log.error(`processChange [${label}/${i}]:`, e.message)
              );
            } else {
              consecutiveEmpty++;
              if (getAddrState(entry.address, wallet.name).balanceSat === null)
                setAddrState(entry.address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: null }, wallet.name);
            }
          }
          totalOk++;
        } catch(e) {
          if (e.isAbort) throw e; // propaga AbortScanError sem engolir
          // Socket destroyed during await subscribe/getHistory → treat as abort
          if (!electrum.connected || _reconnectRequested) throw new AbortScanError();
          log.error(`  subscribe [${label}/${i}] ${entry.address.slice(0,16)}…: ${e.message}`);
          consecutiveEmpty++;
        }

        await sleep(getCFG().subscribeDelayMs);
        checkAbort(); // ← check after each sleep
        i++;

        // addr() is a fixed address — no derivation needed, process once
        if (isSingleAddress) break;
      }

      const total = wallet.addresses.filter(a => a.chain === chain).length;
      log.info(`  ${wallet.name} [${label}]: ${total} addresses, last used idx ${lastUsed}`);
    }
  }

  initialScanDone = true;
  log.ok(`${totalOk} scripthashes subscribed — ${shMap.size} scriptHashes / ${addrMap.size} monitored entries ⚡`);
}


// ─── BTC/USD PRICE ────────────────────────────────────────────────────────────
let _priceCache = { usd: null, updatedAt: null };

// PRICE_APIS is a function so the currency is read from config at
// call time — allows changing currency without restarting the monitor.
function getPriceApis() {
  const cur = (getCFG().currency || 'USD').toUpperCase();
  const curLower = cur.toLowerCase();
  return [
    {
      id:    'coingecko',
      name:  'CoinGecko',
      url:   `https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=${curLower}`,
      parse: (d) => JSON.parse(d)?.bitcoin?.[curLower],
    },
    {
      id:    'binance',
      name:  'Binance',
      url:   `https://api.binance.com/api/v3/ticker/price?symbol=BTC${cur}`,
      parse: (d) => parseFloat(JSON.parse(d)?.price),
    },
    {
      id:    'blockchain.info',
      name:  'Blockchain.info',
      url:   'https://blockchain.info/ticker',
      parse: (d) => JSON.parse(d)?.[cur]?.last,
    }
  ];
}

async function fetchPrice() {
  const cfg = getCFG();
  const allApis = getPriceApis();
  const order   = cfg.priceApis || [];
  const apis    = allApis.filter(a => order.includes(a.id))
                         .sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  const list    = apis;
  const validIds = allApis.map(a => a.id);

  order.forEach(id => {
    if (!validIds.includes(id)) {
      log.warn(`[config] invalid API: ${id}`);
    }
  });

  if (!list.length) {
    log.warn('  [price] no API configured');
    return null;
  }

  for (const api of list) {
    try {
      const raw = await new Promise((resolve, reject) => {
        const req = https.get(api.url, { headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" } }, res => {
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`HTTP ${res.statusCode}`));
          }
          let d = '';
          res.on('data', c => d += c);
          res.on('end', () => resolve(d));
        });
        req.on('error', reject);
        req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
      });
      const price = api.parse(raw);
      if (price && price > 0 && isFinite(price)) {
        log.info(`  [price] ${api.name} → ${fmtPrice(price)}`);
        _priceCache = { usd: price, updatedAt: Date.now() };
        writeRuntime({ price: _priceCache });
        appendPriceHistory(price);
        return price;
      }
    } catch(e) {
      log.warn(`  [price] ${api.name} failed: ${e.message}`);
    }
  }
  log.warn('  [price] all APIs failed');
  return null;
}


// ─── RECONCILE MEMPOOL→CONFIRMED/DROPPED IN TXHISTORY ──────────────────────
// Scans txhistory.json for entries with mempool:true and:
//   1. If the tx was confirmed → promote (mempool=false, fill height/ts)
//   2. If the tx was dropped or replaced by RBF → mark dropped=true
//      (do not remove, as it is useful historical information)
// Drop detection: the tx no longer appears in the Electrum history of any
// wallet address — neither as confirmed nor as mempool.
// Runs once after subscribeAll completes.
async function reconcileMempoolTxHistory(electrum) {
  const h = readTxHistory();
  let promoted = 0, dropped = 0;

  for (const [walletName, wData] of Object.entries(h)) {
    if (!wData?.txids) continue;

    // Pre-load the full history of all addresses in this wallet
    // to quickly check whether a txid still exists in Electrum.
    // Cache: scriptHash → Set of txids present in Electrum
    const electrumTxids = new Map(); // scriptHash → Set<txid>

    for (const [txid, tx] of Object.entries(wData.txids)) {
      if (!tx.mempool) continue; // only process those still in mempool

      try {
        // ── Passo 1: a tx ainda existe no Electrum? ─────────────────────────
        const txData = await electrum.getTransaction(txid).catch(() => null);

        if (!txData) {
          // getTransaction falhou — tx pode ter sido dropada do mempool
          // Check whether it appears in the history of any wallet address
          let foundInHistory = false;
          for (const [key, info] of addrMap.entries()) {
            if (info.wallet.name !== walletName) continue;
            let shTxids = electrumTxids.get(info.scriptHash);
            if (!shTxids) {
              const hist = await electrum.getHistory(info.scriptHash).catch(() => []);
              shTxids = new Set(hist.map(e => e.tx_hash));
              electrumTxids.set(info.scriptHash, shTxids);
            }
            if (shTxids.has(txid)) { foundInHistory = true; break; }
          }

          if (!foundInHistory) {
            // Tx sumiu completamente — dropped ou RBF
            tx.mempool  = false;
            tx.dropped  = true;
            tx.droppedAt = Date.now();
            dropped++;
            log.warn(`  [reconcile] ${txid.slice(0,16)}… DROPPED/RBF — removida do mempool sem confirmar (${walletName})`);
          }
          continue;
        }

        // ── Passo 2: tx existe — confirmada? ────────────────────────────────
        const isConfirmed = (txData.confirmations > 0) || !!txData.blockhash || !!txData.blocktime;

        if (!isConfirmed) {
          // Still in mempool — no action
          continue;
        }

        // ── Passo 3: promove mempool→confirmado, busca height ────────────────
        let height = null;
        for (const [key, info] of addrMap.entries()) {
          if (info.wallet.name !== walletName) continue;
          let shTxids = electrumTxids.get(info.scriptHash);
          if (!shTxids) {
            const hist = await electrum.getHistory(info.scriptHash).catch(() => []);
            shTxids = new Set(hist.map(e => e.tx_hash));
            electrumTxids.set(info.scriptHash, shTxids);
            // Aproveita para pegar o height desta entrada
            const entry = hist.find(e => e.tx_hash === txid);
            if (entry?.height > 0 && !height) height = entry.height;
          } else if (shTxids.has(txid)) {
            // We have the set but need the height — redo getHistory only if needed
            if (!height) {
              const hist = await electrum.getHistory(info.scriptHash).catch(() => []);
              const entry = hist.find(e => e.tx_hash === txid);
              if (entry?.height > 0) height = entry.height;
            }
          }
          if (height) break;
        }

        tx.mempool = false;
        if (height)              tx.height = height;
        if (txData.blocktime)    tx.ts     = txData.blocktime * 1000;
        promoted++;
        log.info(`  [reconcile] ${txid.slice(0,16)}… promoted mempool→${height ? 'block #'+height : 'confirmed'} (${walletName})`);

      } catch(e) {
        log.warn(`  [reconcile] ${txid.slice(0,16)}…: ${e.message}`);
      }
    }
  }

  const changed = promoted + dropped;
  if (changed > 0) {
    writeTxHistory(h);
    if (promoted) log.ok(`[reconcile] ${promoted} tx(s) promovidas mempool→confirmado`);
    if (dropped)  log.warn(`[reconcile] ${dropped} tx(s) marcadas como DROPPED/RBF`);
  } else {
    log.info('[reconcile] no pending mempool txs to reconcile');
  }
}

// ─── BTC/USD PRICE CHECK LOOP ───────────────────────────────────────────────
// schedulePriceCheck, applyPriceReference, and checkPrice are at module level
// so hotReloadConfig can trigger an immediate fetch on currency change.

function schedulePriceCheck(immediate = false) {
  const interval = immediate ? 0 : getCFG().priceCheckIntervalSec * 1000;
  _priceTimerRef = setTimeout(async () => {
    _priceTimerRef = null;
    if (_priceRunning) { schedulePriceCheck(); return; } // already running — defer
    _priceRunning = true;
    try { await checkPrice(); } catch(e) { log.warn(`checkPrice: ${e.message}`); }
    _priceRunning = false;
    schedulePriceCheck();
  }, interval);
}

// Track the priceReference already applied — avoids re-applying on each check
// Apply priceReference from config if it is a new value (different from last applied).
// Validate ±priceRefMaxDeviationPct% relative to current price.
function applyPriceReference(currentPrice) {
  const cfgRef = getNotifValue('priceReference', null);
  if (!cfgRef || cfgRef <= 0) return null; // null = no manual reference

  // Already applied previously — do not re-apply
  if (cfgRef === _appliedCfgRef) return null;

  const maxDev = (getCFG().priceRefMaxDeviationPct || 20) / 100;
  const lo = currentPrice * (1 - maxDev);
  const hi = currentPrice * (1 + maxDev);
  if (cfgRef < lo || cfgRef > hi) {
    log.warn(`  [price] priceReference=${fmtPrice(cfgRef)} outside ±${getCFG().priceRefMaxDeviationPct||20}% (${fmtPrice(Math.round(lo))}–${fmtPrice(Math.round(hi))}) — ignored`);
    _appliedCfgRef = cfgRef; // mark as processed to avoid logging every cycle
    return null;
  }

  _appliedCfgRef = cfgRef;
  log.info(`  [price] manual reference applied: ${fmtPrice(cfgRef)}`);
  return cfgRef;
}

async function checkPrice() {
  const enabled   = notifEnabled('priceChange');
  const rawPct = getNotifValue('priceThresholdPct', 1);
  try {
    const price = await fetchPrice();
    if (!price) return;

    // Convert % → USD and apply min/max range
    const _cfgLimits = getCFG();
    const minPct     = _cfgLimits.priceThresholdMinPct || 1;
    const maxPct     = _cfgLimits.priceThresholdMaxPct || 50;
    const clampedPct = Math.min(Math.max(rawPct, minPct), maxPct);
    if (clampedPct !== rawPct) {
      if (!_threshWarnLogged) {
        log.warn(`  [price] priceThresholdPct ${rawPct}% out of range — corrected to ${clampedPct}% in config`);
        _threshWarnLogged = true;
        saveThresholdPct(clampedPct); // fix in config.json
      }
    } else {
      _threshWarnLogged = false;
    }
    const threshold = Math.ceil(price * clampedPct / 100);
    log.info(`  [price] threshold: ${clampedPct}% = ${fmtPrice(threshold)}`);

    // First run (or first run after currency change) — set reference silently.
    // Never notify here: on currency change the "delta" would just be the
    // exchange rate difference, not a real price move.
    if (_lastNotifiedPrice === null) {
      // On normal boot: respect the manual priceReference from config if set.
      // After a currency change: _appliedCfgRef was cleared and priceReference
      // was set to null in config — applyPriceReference() will return null,
      // so price is always used as baseline regardless.
      const manualRef = applyPriceReference(price);
      _lastNotifiedPrice = manualRef !== null ? manualRef : price;
      savePriceReference(_lastNotifiedPrice);
      log.info(`  [price] new reference set: ${fmtPrice(_lastNotifiedPrice)} | threshold: ${clampedPct}% (${fmtPrice(threshold)}) | no notification (baseline)`);
      return;
    }

    // Check for new manual reference in config (different from last applied)
    const manualRef = applyPriceReference(price);
    if (manualRef !== null) {
      _lastNotifiedPrice = manualRef;
      log.info(`  [price] manual reference set: ${fmtPrice(_lastNotifiedPrice)}`);
    }

    const delta = Math.abs(price - _lastNotifiedPrice);
    log.info(`  [price] current=${fmtPrice(price)} ref=${fmtPrice(_lastNotifiedPrice)} Δ=${fmtPrice(Math.round(delta))} threshold=${clampedPct}%(${fmtPrice(threshold)}) notify=${enabled})`);

    if (enabled && delta >= threshold) {
      const dir  = price > _lastNotifiedPrice ? '📈' : '📉';
      const sign = price > _lastNotifiedPrice ? '+' : '-';
      await sendNotification(
        t('price_change', {
          dir,
          price:     fmtPrice(price),
          sign,
          delta:     fmtPrice(Math.round(delta)),
          pct:       (delta / _lastNotifiedPrice * 100).toFixed(2),
          ref:       fmtPrice(Math.round(_lastNotifiedPrice)),
          threshold: clampedPct,
          time:      now(),
        })
      );
      log.info(`${dir} BTC ${fmtPrice(price)} (Δ${sign}${fmtPrice(Math.round(delta))}) → Telegram`);
      // Update reference after notifying — next notification starts from current price
      _lastNotifiedPrice = price;
      _appliedCfgRef     = price; // prevents config from re-applying the old value
      savePriceReference(price);  // persist to config.json
    } else if (!enabled) {
      // Notification off — track price to avoid accumulating delta when re-enabled
      _lastNotifiedPrice = price;
    }
    // Notification on but delta below threshold — ref unchanged, delta keeps accumulating
  } catch(e) { log.warn(`checkPrice: ${e.message}`); }
}

async function run() {
  log.info('╔═════════════════════════════════════════╗');
  log.info('║  BitTrack Monitor v5 — Electrum Server  ║');
  log.info('║     scripthash.subscribe + Telegram     ║');
  log.info('╚═════════════════════════════════════════╝');

  loadState();
  loadWallets();
  reconcileGapOnBoot(); // reconcile gapLimit reduction that occurred offline

  // Activate lock immediately — panel is blocked until boot is complete
  writeRuntime({ lock: { active: true, msg: 'iniciando...', since: Date.now(), timeoutAt: null } });
  log.info('boot started — runtime lock activated');

  // ── Detect missing/empty txhistory and force full resync ────────────────────
  // If txhistory.json does not exist or is empty, invalidate the statusHash of
  // all addresses with history in state — this forces processChange
  // a rodar o catch-up completo em cada um, reconstruindo o txhistory do zero.
  // Addresses without history (balanceSat=0, txids=[]) are preserved.
  const _txHistoryRaw = (() => { try { return JSON.parse(fs.readFileSync(TX_HISTORY_FILE, 'utf8')); } catch { return null; } })();
  const _txHistoryEmpty = !_txHistoryRaw || Object.keys(_txHistoryRaw).length === 0;
  if (_txHistoryEmpty) {
    let invalidated = 0;
    for (const [walletName, wData] of Object.entries(state)) {
      if (typeof wData !== 'object') continue;
      for (const labelData of Object.values(wData)) {
        if (typeof labelData !== 'object') continue;
        for (const addrData of Object.values(labelData)) {
          if (!addrData || typeof addrData !== 'object') continue;
          // Only invalidate addresses that have history — do not touch empty addresses
          if ((addrData.txids?.length || 0) > 0 || (addrData.mempoolTxids?.length || 0) > 0) {
            addrData.statusHash = null; // force reprocessing in subscribeAll
            invalidated++;
          }
        }
      }
    }
    if (invalidated > 0) {
      log.info(`[boot] txhistory absent — ${invalidated} address(es) with history flagged for resync`);
    }
  }

  const _initCfg = getCFG();
  log.info(`Addresses: ${addrMap.size} | Gap limit: ${_initCfg.gapLimit}`);
  log.info(`Electrum Server: ${_initCfg.electrum.host}:${_initCfg.electrum.port} ${_initCfg.electrum.tls ? '(TLS)' : '(TCP)'}`);

  if (!_initCfg.telegram.enabled || !_initCfg.telegram.token || !_initCfg.telegram.chatId)
    log.warn('Telegram not configured or disabled');
  if (_initCfg.ntfy?.enabled && !_initCfg.ntfy?.url)
    log.warn('ntfy enabled but URL not configured');


  log.info(`  [price] loop started — interval: ${getCFG().priceCheckIntervalSec}s`);
  schedulePriceCheck(true); // run immediately and schedule subsequent checks
  // ─────────────────────────────────────────────────────────────────────────

  while (true) {
    const cfg     = getCFG();
    const electrum = new ElectrumClient();
    _activeElectrum = electrum;
    // Reset reconnect flags at the start of each attempt — any signal
    // arriving DURING connect() will be processed in the next iteration.
    _reconnectRequested  = false;
    _serverChangePending = false;

    try {
      await electrum.connect();

      // Handshake
      const ver = await electrum.call('server.version', ['BitTrack/5.0', '1.4']);
      log.info(`Server: ${Array.isArray(ver) ? ver.join(' / ') : ver}`);

      await sendNotification(msgStartup(addrMap.size, getCFG().gapLimit));

      await subscribeAll(electrum);

      // Reconcilia txs que estavam na mempool e foram confirmadas enquanto offline
      await reconcileMempoolTxHistory(electrum).catch(e =>
        log.warn(`[reconcile] erro: ${e.message}`)
      );

      // Initial fee fetch right after connection
      await fetchAndSaveFees(electrum).catch(() => {});

      // Boot complete — only now release the panel
      if (!_reconnectRequested) {
        writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
        log.info('boot complete — runtime lock released');
      }

      // Keepalive + fee update on each ping
      const pingTimer = setInterval(async () => {
        if (!electrum.connected) { clearInterval(pingTimer); return; }
        try {
          await electrum.ping();
          await fetchAndSaveFees(electrum).catch(() => {});
        } catch(e) {
          log.warn(`  [ping] failed (${e.message}) — forcing reconnect`);
          electrum.disconnect();
        }
      }, cfg.pingInterval);

      // Wait for disconnection or reconnect request due to server switch
      await new Promise(resolve => {
        const check = setInterval(() => {
          if (!electrum.connected || _reconnectRequested) {
            clearInterval(check);
            clearInterval(pingTimer);
            resolve();
          }
        }, 1000);
      });

    } catch(e) {
      // AbortScanError → intentional subscribeAll interruption — do not log or release lock.
      // "connection closed" with _reconnectRequested → hot-reload destroyed the socket
      // intentionally to force reconnect — also do not release lock here.
      const intentional = e.isAbort || (_reconnectRequested && e.message === 'connection closed');
      if (!intentional) {
        // Real connection failure (timeout, refusal, invalid host) — release lock
        // immediately with the error for the panel to show without waiting for reconnectDelay.
        log.error(`Electrum Server: ${e.message}`);
        writeRuntime({
          lock:     { active: false, msg: '', since: null, timeoutAt: null },
          electrum: { connected: false, error: e.message, since: Date.now() },
        });
      }
    }

    electrum.disconnect();
    _activeElectrum = null;
    const _cfg2   = getCFG();
    const _noHost = !_cfg2.electrum?.host;

    if (_noHost) {
      log.warn('Electrum not configured — waiting 30s. Set electrum.host in the panel or config.json');
      // Wait 30s but still allow interruption by a server switch
      await new Promise(resolve => {
        _reconnectTimer = setTimeout(() => { _reconnectTimer = null; resolve(); }, 30000);
        const interrupt = setInterval(() => {
          if (_reconnectRequested) {
            clearInterval(interrupt);
            if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
            resolve();
          }
        }, 500);
      });
    } else if (_reconnectRequested) {
      // Server switch detected — small 300ms pause and reconnect
      log.info(`Reconectando ao novo servidor em 300ms…`);
      await sleep(300);
    } else {
      // Network failure — always wait the full 10s (not interruptible by polling)
      const delay = _cfg2.reconnectDelay || 10000;
      log.info(`Reconectando em ${delay / 1000}s…`);
      await new Promise(resolve => {
        _reconnectTimer = setTimeout(() => { _reconnectTimer = null; resolve(); }, delay);
        // Still allows interruption if a server switch occurs during the wait
        const interrupt = setInterval(() => {
          if (_reconnectRequested) {
            clearInterval(interrupt);
            if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
            resolve();
          }
        }, 500);
      });
    }
  }
}

run().catch(e => { log.error('Fatal:', e.message); process.exit(1); });

// ─── HOT-RELOAD ──────────────────────────────────────────────────────────────
// Detects changes in config.json and wallets.json without restarting the process.
//
// config.json:
//   - Telegram / notifications / gapLimit / maxIndex → applies in real time
//     (already works because getNotifications() and getCFG() read from disk)
//   - host/port/TLS changed → signals reconnect to new server
//
// wallets.json:
//   - New descriptor → subscribe only new addresses, without reprocessing
//     the already known ones
//   - Descriptor removed → purge addrMap, shMap and state immediately;
//     the Electrum server still sends events but they are ignored because
//     the scriptHash no longer exists in shMap

// ─── REBALANCE GAP ───────────────────────────────────────────────────────────
// Called when gapLimit changes in config.json.
//
// REDUCTION: removes empty addresses (no balance and no
//   txs) beyond the new gap — respecting the gap from the last
//   address with history.
//
// INCREASE: immediately derives and subscribes new addresses in all
//   wallets.

// Serialized queue — prevents concurrent executions when gapLimit is changed
// multiple times in rapid succession. The second rebalance starts only after the first
// finishes, ensuring state is consistent for cutoff calculation.
let _rebalanceQueue = Promise.resolve();
function queueRebalance(prevGap, newGap, electrum) {
  _rebalanceQueue = _rebalanceQueue
    .then(() => rebalanceGap(prevGap, newGap, electrum))
    .catch(e => log.error('[gap] rebalanceGap:', e.message));
}

async function rebalanceGap(prevGap, newGap, electrum) {
  if (!electrum?.connected) return;
  log.info(`[gap] gapLimit changed: ${prevGap} → ${newGap}`);

  for (const wallet of wallets) {
    if (!wallet.descriptor) continue;
    const hrp      = walletHrp(wallet);
    const isSingle = wallet.descriptor.startsWith('addr(');
    if (isSingle) continue;
    const chains = [0, 1];

    for (const chain of chains) {
      const label    = chain === 0 ? 'ext' : 'chg';
      const addrs    = (wallet.addresses || []).filter(a => a.chain === chain)
                         .sort((a, b) => a.index - b.index);
      if (!addrs.length) continue;

      // Index of the last address WITH history (balance > 0 or txs > 0)
      let lastUsed = -1;
      for (const a of addrs) {
        const st = getAddrState(a.address, wallet.name);
        if ((st.balanceSat || 0) > 0 || (st.txids?.length || 0) > 0 || (st.mempoolTxids?.length || 0) > 0) {
          lastUsed = a.index;
        }
      }

      // ── REDUCTION: purge empties beyond the new gap ──────────────────────────
      if (newGap < prevGap) {
        const startIdx = wallet.startIndex ?? 0;
        // cutoff = last allowed index:
        //   - If addresses with history exist: lastUsed + newGap
        //   - If wallet is completely empty: startIdx + newGap - 1
        const base   = lastUsed >= 0 ? lastUsed : startIdx - 1;
        const cutoff = base + newGap;
        let purged = 0;

        for (const a of [...addrs]) {
          if (a.index <= cutoff) continue;
          const st = getAddrState(a.address, wallet.name);
          const hasHistory = (st.balanceSat || 0) > 0
            || (st.txids?.length || 0) > 0
            || (st.mempoolTxids?.length || 0) > 0;
          if (hasHistory) continue; // never remove an address with history

          // Remove de addrMap
          addrMap.delete(a.address + '|' + wallet.name);
          // Remove de shMap
          const shList = shMap.get(a.scriptHash);
          if (shList) {
            const filtered = shList.filter(e => e.wallet.name !== wallet.name || e.address !== a.address);
            if (filtered.length) shMap.set(a.scriptHash, filtered);
            else shMap.delete(a.scriptHash);
          }
          // Remove de wallet.addresses
          const wIdx = wallet.addresses.indexOf(a);
          if (wIdx !== -1) wallet.addresses.splice(wIdx, 1);
          // Remove from in-memory state — without this saveState would rewrite the address
          const lbl = chain === 0 ? 'externo' : 'change';
          if (state[wallet.name]?.[lbl]) {
            delete state[wallet.name][lbl][a.address];
          }
          purged++;
        }

        const remaining = wallet.addresses.filter(a => a.chain === chain).length;
        if (purged > 0) {
          log.info(`  [gap] ${wallet.name} [${label}]: ${purged} addresses removed (cutoff idx ${cutoff}, remaining ${remaining})`);
          updateLockMsg(`reducing gap limit… "${wallet.name}" — ${purged} addresses removed`);
          saveState();
        } else {
          log.info(`  [gap] ${wallet.name} [${label}]: no addresses removed (cutoff idx ${cutoff}, total ${remaining})`);
        }
      }

      // ── INCREASE: sequential scan from the last address with tx ────────────────
      if (newGap > prevGap) {
        const desc             = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;
        const lastIdx          = addrs.length ? Math.max(...addrs.map(a => a.index)) : -1;
        const startIdx         = wallet.startIndex ?? 0;
        let consecutiveEmpty   = 0;
        let i                  = Math.max(lastUsed + 1, startIdx);
        let added              = 0;
        let lastUsedInScan     = lastUsed;

        // Estimate of new addresses to index in this chain
        const _needed = newGap - Math.max(0, lastIdx - (lastUsed >= 0 ? lastUsed : startIdx - 1));
        let _done = 0;

        while (consecutiveEmpty < newGap && i <= getCFG().maxIndex) {
          const existingEntry = wallet.addresses.find(a => a.chain === chain && a.index === i);
          if (existingEntry) {
            const st = getAddrState(existingEntry.address, wallet.name);
            const hasHist = (st.balanceSat || 0) > 0 || (st.txids?.length || 0) > 0 || (st.mempoolTxids?.length || 0) > 0;
            if (hasHist) {
              consecutiveEmpty = 0;
              lastUsedInScan   = i;
            } else {
              consecutiveEmpty++;
            }
            i++;
            continue;
          }

          const entry = deriveOne(desc, hrp, i, chain);
          if (!entry) { i++; consecutiveEmpty++; continue; }

          wallet.addresses.push({ ...entry, chain, index: i });
          registerAddress(entry, wallet, chain, i);

          try {
            const status = await electrum.subscribe(entry.scriptHash);
            if (status) {
              consecutiveEmpty  = 0;
              lastUsedInScan    = i;
              processChange(electrum, entry.scriptHash, status).catch(() => {});
            } else {
              consecutiveEmpty++;
              setAddrState(entry.address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: null }, wallet.name);
            }
          } catch(e) {
            log.warn(`  [gap] subscribe ${entry.address.slice(0,16)}…: ${e.message}`);
            consecutiveEmpty++;
          }

          _done++;
          updateLockMsg(`increasing gap limit… "${wallet.name}" [${label === 'ext' ? 'external' : 'change'}] ${_done}/${Math.max(_done, _needed)} addresses`);

          await sleep(getCFG().subscribeDelayMs);
          added++;
          i++;
        }

        if (added > 0)
          log.info(`  [gap] ${wallet.name} [${label}]: +${added} addresses scanned, last with tx idx ${lastUsedInScan}`);
      }
    }
  }

  // Release UI lock after completion
  writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
  log.info('[gap] rebalanceGap complete — runtime lock released');
}

function hotReloadConfig(prevRaw) {
  const cfgFile = path.join(dataDir, 'config.json');
  let newRaw = '';
  try { newRaw = fs.readFileSync(cfgFile, 'utf8'); } catch { return; }
  if (newRaw === prevRaw) return;

  const prev = (() => { try { return JSON.parse(prevRaw); } catch { return {}; } })();
  const next = (() => { try { return JSON.parse(newRaw); } catch(e) { return null; } })();
  if (!next) {
    // Arquivo pode estar sendo escrito — aguarda 500ms e tenta novamente
    setTimeout(() => hotReloadConfig(prevRaw), 500);
    return;
  }

  const pe = prev.electrum || {};
  const ne = next.electrum || {};
  const serverChanged = pe.host !== ne.host || pe.port !== ne.port || pe.tls !== ne.tls;

  if (serverChanged) {
    // Ignore if a server switch is already pending — prevents multiple reconnects
    // triggered by 3s polling while the loop is still restarting.
    if (_serverChangePending) return;
    _serverChangePending = true;
    log.info(`[hot-reload] Servidor Electrum alterado → ${ne.host}:${ne.port} — reconectando...`);
    _reconnectRequested = true;
    // Cancel the reconnect sleep immediately
    if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
    // Destroy the socket immediately — the loop catch will ignore the error
    // because _reconnectRequested is already true.
    if (_activeElectrum) {
      try { if (_activeElectrum.socket) _activeElectrum.socket.destroy(); } catch {}
      try { _activeElectrum.disconnect(); } catch {}
    }
    return;
  }

  // Detect and log all relevant changes
  const changes = [];

  // Compare flat sections with friendly label
  const checks = [
    ['telegram.token',                   (o) => o.telegram?.token,                     'Telegram token'],
    ['telegram.chatId',                  (o) => o.telegram?.chatId,                    'Telegram chatId'],
    ['general.mempoolExplorer',          (o) => o.general?.mempoolExplorer,            'mempoolExplorer'],
    ['general.currency',                 (o) => o.general?.currency,                   'currency'],
    ['general.timezone',                 (o) => o.general?.timezone,                   'timezone'],
    ['monitor.gapLimit',                 (o) => o.monitor?.gapLimit,                   'gapLimit'],
    ['monitor.maxIndex',                 (o) => o.monitor?.maxIndex,                   'maxIndex'],
    ['monitor.pingIntervalSec',          (o) => o.monitor?.pingIntervalSec,            'pingIntervalSec'],
    ['monitor.subscribeDelayMs',         (o) => o.monitor?.subscribeDelayMs,           'subscribeDelayMs'],
    ['monitor.priceCheckIntervalSec',    (o) => o.monitor?.priceCheckIntervalSec,      'priceCheckIntervalSec'],
    ['monitor.priceApis',                (o) => JSON.stringify(o.monitor?.priceApis),  'priceApis'],
    ['monitor.priceRefMaxDeviationPct',  (o) => o.monitor?.priceRefMaxDeviationPct,    'priceRefMaxDeviationPct'],
    ['monitor.priceThresholdMinPct',     (o) => o.monitor?.priceThresholdMinPct,       'priceThresholdMinPct'],
    ['monitor.priceThresholdMaxPct',     (o) => o.monitor?.priceThresholdMaxPct,       'priceThresholdMaxPct'],
    ['notifications.mempoolPending',     (o) => o.notifications?.mempoolPending,       'mempoolPending'],
    ['notifications.txConfirmed',        (o) => o.notifications?.txConfirmed,          'txConfirmed'],
    ['notifications.everyBlock',         (o) => o.notifications?.everyBlock,           'everyBlock'],
    ['notifications.blockIntervalMin',   (o) => o.notifications?.blockIntervalMin,     'blockIntervalMin'],
    ['notifications.priceChange',        (o) => o.notifications?.priceChange,          'priceChange'],
    ['notifications.priceThresholdPct',  (o) => o.notifications?.priceThresholdPct,    'priceThresholdPct'],
    ['notifications.priceReference',     (o) => o.notifications?.priceReference,       'priceReference'],
  ];

  for (const [, getter, label] of checks) {
    const pv = getter(prev);
    const nv = getter(next);
    if (JSON.stringify(pv) !== JSON.stringify(nv))
      changes.push(`${label}: ${JSON.stringify(pv)} → ${JSON.stringify(nv)}`);
  }

  if (changes.length)
    log.info(`[hot-reload] config.json updated:\n  ${changes.join('\n  ')}`);
  else
    log.info('[hot-reload] config.json updated — no relevant changes detected');

  // Check for gapLimit change
  const prevGap = (prev.monitor || {}).gapLimit || 10;
  const nextGap = (next.monitor || {}).gapLimit || 10;
  if (prevGap !== nextGap && _activeElectrum?.connected) {
    queueRebalance(prevGap, nextGap, _activeElectrum);
  }

  // Check for currency change — reset reference and fetch new price immediately.
  // Cancels the pending timer and schedules an immediate run so the new price
  // is fetched right away instead of waiting for the next regular cycle.
  const prevCurrency = (prev.general || {}).currency;
  const nextCurrency = (next.general || {}).currency;
  if (prevCurrency && nextCurrency && prevCurrency !== nextCurrency) {
    log.info(`[hot-reload] currency changed: ${prevCurrency} → ${nextCurrency} — scheduling immediate price fetch`);
    if (_priceTimerRef) { clearTimeout(_priceTimerRef); _priceTimerRef = null; }
    // Trigger an immediate price check cycle with reset reference
    _priceTimerRef = setTimeout(async () => {
      _priceTimerRef = null;
      if (_priceRunning) return; // already running — it will reschedule itself
      _priceRunning = true;
      _lastNotifiedPrice = null;
      _appliedCfgRef = null;
      savePriceReference(null);
      log.info('  [price] currency changed — reference cleared, fetching new baseline price');
      try { await checkPrice(); } catch(e) { log.warn(`checkPrice (currency reset): ${e.message}`); }
      _priceRunning = false;
      schedulePriceCheck(); // resume normal interval
    }, 0);
  }
}

async function hotReloadWallets(electrum) {
  if (!electrum?.connected) return;
  const walletsFile = path.join(dataDir, 'wallets.json');
  let newList = [];
  try { newList = JSON.parse(fs.readFileSync(walletsFile, 'utf8')); } catch { return; }

  const newDescriptors  = new Set(newList.map(w => w.descriptor).filter(Boolean));
  const knownDescriptors = new Set(wallets.map(w => w.descriptor));

  // ── Removed descriptors → clear addrMap, shMap and state ─────────────────
  const removed = wallets.filter(w => w.descriptor && !newDescriptors.has(w.descriptor));
  if (removed.length) {
    for (const wallet of removed) {
      let count = 0;
      // Remove all addresses of this wallet from addrMap and shMap
      for (const [key, info] of addrMap.entries()) {
        if (info.wallet.name !== wallet.name) continue;
        addrMap.delete(key);
        // Remove shMap entry for this wallet
        const shList = shMap.get(info.scriptHash);
        if (shList) {
          const filtered = shList.filter(e => e.wallet.name !== wallet.name);
          if (filtered.length) shMap.set(info.scriptHash, filtered);
          else shMap.delete(info.scriptHash);
        }
        count++;
      }
      // Remove from state
      delete state[wallet.name];
      saveState();

      // Remove from txHistory — prevents transactions from the removed wallet
      // from appearing in history after removal or contaminating future re-additions.
      try {
        const th = readTxHistory();
        if (th[wallet.name]) {
          delete th[wallet.name];
          writeTxHistory(th);
          log.info(`[hot-reload] "${wallet.name}" — txHistory limpo`);
        }
      } catch(e) { log.warn(`[hot-reload] limpeza txHistory "${wallet.name}": ${e.message}`); }

      log.info(`[hot-reload] "${wallet.name}" removed — ${count} addresses purged from memory`);
    }
    // Update in-memory list
    wallets.splice(0, wallets.length, ...wallets.filter(w => newDescriptors.has(w.descriptor)));
  }

  // ── New descriptors → subscribe ────────────────────────────────────────
  const added = newList.filter(w => w.descriptor && !knownDescriptors.has(w.descriptor));

  if (!added.length && !removed.length) {
    // No descriptor changes — but notify settings may have changed.
    // Sync them in-memory so notifEnabled() picks them up immediately.
    let notifyChanged = 0;
    for (const updated of newList) {
      const existing = wallets.find(w => w.descriptor === updated.descriptor);
      if (!existing) continue;
      const prevNotify = JSON.stringify(existing.notify);
      const nextNotify = JSON.stringify(updated.notify);
      if (prevNotify !== nextNotify) {
        existing.notify = updated.notify;
        notifyChanged++;
        log.info(`[hot-reload] "${existing.name}" — notify settings updated: ${nextNotify}`);
      }
    }
    if (notifyChanged) {
      log.info(`[hot-reload] ${notifyChanged} wallet(s) had notify settings updated in-memory`);
    } else {
      log.info('[hot-reload] wallets.json updated — no descriptor or notify changes');
    }
    return;
  }
  if (!added.length) {
    // Only removals — release lock immediately
    writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
    log.info('[hot-reload] removal complete — runtime lock released');
    return;
  }

  log.info(`[hot-reload] ${added.length} novo(s) descritor(es) detectado(s) — subscrevendo...`);

  // For newly added wallets, ensure there is no residual txHistory
  // from a wallet with the same name that was previously removed.
  for (const wallet of added) {
    try {
      const th = readTxHistory();
      if (th[wallet.name]) {
        delete th[wallet.name];
        writeTxHistory(th);
        log.info(`[hot-reload] txHistory residual de "${wallet.name}" limpo antes de re-indexar`);
      }
    } catch(e) { log.warn(`[hot-reload] txHistory cleanup before adding "${wallet.name}": ${e.message}`); }
  }

  // Calculate estimated total addresses to index (for progress display)
  const _cfg0 = getCFG();
  let _totalNeeded = 0;
  for (const w of added) {
    _totalNeeded += w.descriptor.startsWith('addr(') ? 1 : _cfg0.gapLimit * 2;
  }
  let _totalDone = 0;

  for (const wallet of added) {
    wallet.addresses = wallet.addresses || [];
    wallets.push(wallet);
    const hrp       = walletHrp(wallet);
    const startIdx  = wallet.startIndex ?? 0;
    const isSingle  = wallet.descriptor.startsWith('addr(');
    const chains    = isSingle ? [0] : [0, 1];

    for (const chain of chains) {
      const desc  = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;
      const label = chain === 0 ? 'ext' : 'chg';
      let consecutiveEmpty = 0;
      let i = startIdx;
      let lastUsed = startIdx - 1;
      const cfg = getCFG();

      while (consecutiveEmpty < cfg.gapLimit && i <= cfg.maxIndex) {
        let entry = wallet.addresses.find(a => a.chain === chain && a.index === i);
        if (!entry) {
          entry = deriveOne(desc, hrp, i, chain);
          if (!entry) { i++; consecutiveEmpty++; continue; }
          wallet.addresses.push({ ...entry, chain, index: i });
          registerAddress(entry, wallet, chain, i);
        } else if (!shMap.get(entry.scriptHash)?.some(e => e.wallet.name === wallet.name)) {
          registerAddress(entry, wallet, chain, i);
        }

        try {
          const statusHash = await electrum.subscribe(entry.scriptHash);
          if (statusHash) {
            consecutiveEmpty = 0;
            lastUsed = i;
            processChange(electrum, entry.scriptHash, statusHash).catch(() => {});
          } else {
            const hist = await electrum.getHistory(entry.scriptHash).catch(() => []);
            if (hist.length) {
              consecutiveEmpty = 0;
              lastUsed = i;
              processChange(electrum, entry.scriptHash, null).catch(() => {});
            } else {
              consecutiveEmpty++;
              if (getAddrState(entry.address, wallet.name).balanceSat === null)
                setAddrState(entry.address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: null }, wallet.name);
            }
          }
        } catch(e) {
          log.error(`  [hot-reload] subscribe [${label}/${i}] ${entry.address.slice(0,16)}…: ${e.message}`);
          consecutiveEmpty++;
        }

        _totalDone++;
        updateLockMsg(`indexing "${wallet.name}" [${label}]… ${_totalDone}/${_totalNeeded} addresses`);

        await sleep(getCFG().subscribeDelayMs);
        i++;
        if (isSingle) break;
      }

      const total = wallet.addresses.filter(a => a.chain === chain).length;
      log.info(`  [hot-reload] ${wallet.name} [${label}]: ${total} addresses subscribed, last used idx ${lastUsed}`);
    }
  }

  // Release the UI lock after all added descriptors have been indexed
  writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
  log.info('[hot-reload] wallets indexed — runtime lock released');
}

// Watcher with 1.5s debounce
let _cfgRaw     = '';
let _walletsRaw = '';
let _hotTimer   = null;

try { _cfgRaw     = fs.readFileSync(path.join(dataDir, 'config.json'),  'utf8').trim(); } catch {}
try { _walletsRaw = fs.readFileSync(path.join(dataDir, 'wallets.json'), 'utf8').trim(); } catch {}

// ─── HOT-RELOAD via content polling ─────────────────────────────────────────
// Reads and compares file content every 3s.
// Works in any Docker/volume environment, independent of inotify.
const POLL_INTERVAL = 3000;

setInterval(() => {
  // ── config.json ──────────────────────────────────────────────────────────
  try {
    const raw = fs.readFileSync(path.join(dataDir, 'config.json'), 'utf8').trim();
    if (raw !== _cfgRaw) {
      // Validate JSON — file may be in the process of being written
      try { JSON.parse(raw); } catch { /* Invalid JSON — wait for next cycle */ return; }
      const prevRaw = _cfgRaw;
      _cfgRaw = raw;
      clearTimeout(_hotTimer);
      _hotTimer = setTimeout(() => hotReloadConfig(prevRaw), 500);
    }
  } catch {}

  // ── wallets.json ─────────────────────────────────────────────────────────
  try {
    const raw = fs.readFileSync(path.join(dataDir, 'wallets.json'), 'utf8').trim();
    if (raw !== _walletsRaw) {
      try { JSON.parse(raw); } catch { return; }
      _walletsRaw = raw;
      clearTimeout(_hotTimer);
      _hotTimer = setTimeout(() => {
        hotReloadWallets(_activeElectrum).catch(e => log.error('[hot-reload] wallets:', e.message));
      }, 500);
    }
  } catch(e) { log.warn(`[poll] wallets.json: ${e.message}`); }
}, POLL_INTERVAL);

log.info(`Hot-reload active — polling every ${POLL_INTERVAL/1000}s (config.json, wallets.json)`);