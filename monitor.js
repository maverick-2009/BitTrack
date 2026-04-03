/**
 * BitTrack Monitor v5 — Electrum Server
 *
 * Fluxo:
 *   1. Deriva endereços via descritor (BIP380/BIP389/Miniscript)
 *   2. Converte cada endereço em scripthash (SHA256 reverso do scriptPubKey)
 *   3. blockchain.scripthash.subscribe → push em tempo real
 *   4. Na mudança: get_history → transaction.get → classifyTx
 *   5. Classifica: recebimento / envio / envio+troco / consolidação
 *   6. Notifica Telegram — uma única mensagem por TXID (anti-duplicata)
 *   7. Gap limit automático para externos e change (sem duplicatas)
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
// Estrutura completa do config com todos os defaults.
// Usada tanto para criar o arquivo do zero quanto para completar campos faltantes.
const CONFIG_DEFAULTS = {
  electrum: {
    name: 'Local',
    host: '',
    port: 50002,
    tls:  false,
  },
  telegram: {
    enabled: true,
    token:   '',
    chatId:  '',
  },
  ntfy: {
    enabled: false,
    url:     '',
    token:   '',
  },
  general: {
    mempoolExplorer: 'https://mempool.space/',
    currency:        'USD',
    timezone:        'America/Sao_Paulo',
    dateLocale:      'pt-BR',
    panelPort:       8585,
  },
  monitor: {
    gapLimit:              10,
    maxIndex:              1000,
    pingIntervalSec:       60,
    subscribeDelayMs:      0,
    priceApis:               ['coingecko', 'binance', 'blockchain.info'],
    priceCheckIntervalSec:   300,
    priceRefMaxDeviationPct: 20,  // desvio máximo permitido para priceReference (%)
    priceThresholdMinPct:    1,   // limiar mínimo em % do preço atual
    priceThresholdMaxPct:    50,  // limiar máximo em % do preço atual
  },
  notifications: {
    mempoolPending:    true,
    txConfirmed:       true,
    everyBlock:        false,
    blockIntervalMin:  0,
    priceChange:       false,
    priceThresholdPct:  1,    // limiar de variação em % do preço atual
    priceReference:  null,   // null = usa o preço atual como referência
  },
};

// Merge profundo: preenche campos faltantes em `target` com valores de `defaults`.
// Nunca sobrescreve valores existentes — apenas adiciona o que falta.
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

// Lê config.json, completa campos faltantes com defaults e regrava se necessário.
// Chamado uma vez no boot via ensureConfig() e depois lido sob demanda via getCFG().
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
      log.info('config.json criado com valores padrão — preencha electrum e telegram antes de iniciar');
    } else {
      log.info('config.json atualizado — campos faltantes preenchidos com valores padrão');
    }
  }
}

// Último config válido lido do disco — usado como fallback se o arquivo estiver corrompido
let _lastValidConfig = null;

// Lê config.json do disco — chamado toda vez que precisar de valores atualizados.
// Não usa cache em memória para que mudanças feitas pelo painel sejam
// refletidas imediatamente sem reiniciar o processo.
function loadConfig() {
  const cfgFile = path.join(dataDir, 'config.json');
  let fc = {};
  try {
    const raw = fs.readFileSync(cfgFile, 'utf8');
    fc = JSON.parse(raw);
    _lastValidConfig = fc; // salva último válido
  } catch {
    // JSON inválido (arquivo sendo escrito) — usa último config válido silenciosamente
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
// CFG é lido do disco sob demanda — use getCFG() em vez de CFG diretamente
// para garantir valores sempre atualizados.
function getCFG() { return loadConfig(); }
// Mantém uma cópia do electrum ativo para comparar mudanças de servidor
let _activeElectrumKey = '';
function electrumKey(e) { return `${e.host}:${e.port}:${e.tls}`; }
const CFG = getCFG(); // usado apenas para inicialização
const RUNTIME_FILE       = path.join(dataDir, 'runtime.json');
const PRICE_HISTORY_FILE = path.join(dataDir, 'historicalprice.json');
const TX_HISTORY_FILE    = path.join(dataDir, 'txhistory.json');

// runtime.json — dados voláteis gravados pelo monitor em tempo real.
// Nunca monitorado pelo fs.watchFile, portanto não causa restart.
// Estrutura atual: { price: { usd, updatedAt }, ... }
function readRuntime() {
  try { return JSON.parse(fs.readFileSync(RUNTIME_FILE, 'utf8')); }
  catch { return {}; }
}

// ─── HISTÓRICO DE PREÇO ──────────────────────────────────────────────────────
// Grava cada ponto de preço em data/historicalprice.json
// Formato: array de { t: timestamp_ms, p: price }
// Limita a 8640 pontos (30 dias × 288 pontos/dia a cada 5 min)
const PRICE_HISTORY_MAX = 8640;

function appendPriceHistory(price) {
  try {
    let history = [];
    try { history = JSON.parse(fs.readFileSync(PRICE_HISTORY_FILE, 'utf8')); }
    catch { history = []; }
    if (!Array.isArray(history)) history = [];
    history.push({ t: Date.now(), p: price });
    if (history.length > PRICE_HISTORY_MAX) history = history.slice(-PRICE_HISTORY_MAX);
    fs.writeFileSync(PRICE_HISTORY_FILE, JSON.stringify(history));
  } catch(e) { log.warn(`appendPriceHistory: ${e.message}`); }
}

// ─── HISTÓRICO DE TRANSAÇÕES ──────────────────────────────────────────────────
// Grava cada transação classificada em data/txhistory.json
// Estrutura: { [walletName]: { txids: { [txid]: { type, valueSat, feeSat, height, ts, mempool, addresses } } } }
// Anti-duplicata via lookup O(1) no objeto txids — nunca reprocessa o que já existe.
// Máximo de 500 txids por carteira (mais antigas removidas).

const TX_HISTORY_MAX = 500;

function readTxHistory() {
  try { return JSON.parse(fs.readFileSync(TX_HISTORY_FILE, 'utf8')); }
  catch { return {}; }
}

function writeTxHistory(data) {
  try { fs.writeFileSync(TX_HISTORY_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { log.warn(`writeTxHistory: ${e.message}`); }
}

// Retorna true se o txid já está registrado para aquela carteira
function txHistoryHas(walletName, txid) {
  try {
    const h = readTxHistory();
    return !!(h[walletName]?.txids?.[txid]);
  } catch { return false; }
}

// Grava uma transação classificada no histórico.
// classification, txid: obrigatórios
// height: número do bloco (null = mempool)
// isPending: bool
// histEntry: entrada do getHistory (pode ter .time para timestamp real)
function appendTxHistory(classification, txid, height, isPending, histEntry) {
  try {
    const { type, walletName } = classification;
    const h = readTxHistory();
    if (!h[walletName]) h[walletName] = { txids: {} };
    if (!h[walletName].txids) h[walletName].txids = {};

    // Anti-duplicata — nunca reprocessa
    if (h[walletName].txids[txid]) {
      // Atualiza apenas se estava como mempool e agora confirmou
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

    // Timestamp: prefere .time do Electrum (unix seconds), senão Date.now()
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

    // Limita a TX_HISTORY_MAX por carteira (remove os mais antigos por height/ts)
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

// Salva o preço de referência em notifications.priceReference no config.json
// sem sobrescrever o resto — o fs.watchFile vai detectar mas o hotReloadConfig
// vai ignorar pois só o priceReference mudou (não é mudança de servidor).
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

// Atualiza apenas a mensagem do lock sem tocar em active/timeoutAt
// Usado durante loops de indexação para mostrar progresso no overlay do painel
function updateLockMsg(msg) {
  const data = readRuntime();
  if (!data.lock?.active) return; // só atualiza se o lock ainda estiver ativo
  data.lock.msg = msg;
  try { fs.writeFileSync(RUNTIME_FILE, JSON.stringify(data, null, 2)); }
  catch(e) { log.warn(`updateLockMsg: ${e.message}`); }
}

// ─── FEES VIA ELECTRUM ───────────────────────────────────────────────────────
// Busca o fee histogram do Electrum e calcula estimativas rápido/médio/lento.
// O histogram é um array de [feeRate, vsize] ordenado por feeRate decrescente.
// Estratégia: acumula vsize até atingir 25% (rápido), 50% (médio), 75% (lento)
// do total. feeRate em sat/vB (já no formato correto do Electrum).
async function fetchAndSaveFees(electrum) {
  try {
    // 1. Buscamos as estimativas oficiais do Bitcoin Core (via Electrum)
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

    // 2. Fallback: Se o estimatefee falhar (-1), usamos o Histograma como plano B
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

    // 3. Garantia final de sanidade (Sanity Check)
    // Se tudo falhar, assume 1 sat/vB. Se houver valores, garante a hierarquia.
    fast = Math.max(1, fast ?? 1);
    med  = Math.max(1, med  ?? fast);
    slow = Math.max(1, slow ?? med);

    // Ordenação lógica: fast >= med >= slow
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

    log.info(`  [fees] rápido=${fastestFee} médio=${halfHourFee} lento=${hourFee} sat/vB`);
  } catch(e) {
    log.warn(`  [fees] erro ao atualizar: ${e.message}`);
  }
}

// ─── PREFERÊNCIAS DE NOTIFICAÇÃO ─────────────────────────────────────────────
// Lê SEMPRE do disco — assim qualquer alteração feita pelo painel é refletida
// imediatamente, sem precisar reiniciar o monitor.
// O config.json é pequeno; a leitura síncrona pontual é negligível.
// Defaults: mempoolPending e txConfirmed = true por padrão;
//           everyBlock e priceChange = false por padrão.
function getNotifications() {
  return getCFG().notifications || {};
}

function notifEnabled(key) {
  const n = getNotifications();
  if (key === 'mempoolPending')  return n.mempoolPending  !== false;
  if (key === 'txConfirmed')     return n.txConfirmed     !== false;
  if (key === 'everyBlock')      return n.everyBlock      === true;
  if (key === 'priceChange')     return n.priceChange     === true;
  return true;
}

// Lê um valor numérico de notifications sem depender do CFG congelado
function getNotifValue(key, fallback) {
  return getNotifications()[key] ?? fallback;
}

// ─── LOGGER ───────────────────────────────────────────────────────────────────
const ts  = () => new Date().toLocaleString(getCFG()?.dateLocale || 'pt-BR', { timeZone: getCFG()?.timezone || 'America/Sao_Paulo', hour12: false }).replace(/\//g, '-').replace(',', '').replace(/\s+/, ' ').slice(0, 19);
const log = {
  info:  (...a) => console.log(`[${ts()}] ℹ️ `, ...a),
  ok:    (...a) => console.log(`[${ts()}] ✅ `, ...a),
  warn:  (...a) => console.warn(`[${ts()}] ⚠️ `, ...a),
  error: (...a) => console.error(`[${ts()}] ❌ `, ...a),
};

ensureConfig(); // garante que config.json existe e está completo

const sleep = ms => new Promise(r => setTimeout(r, ms));
const sats  = s  => (s / 1e8).toFixed(8);

// Formata valor monetário usando a currency configurada em general.currency
function fmtPrice(value) {
  const cur = getCFG().currency || 'USD';
  const sym = cur === 'USD' ? '$' : cur === 'EUR' ? '€' : cur === 'BRL' ? 'R$' : cur + ' ';
  return `${sym}${value.toLocaleString('en-US', { maximumFractionDigits: 2 })}`;
}

const now   = () => new Date().toLocaleString('pt-BR', { timeZone: getCFG().timezone || 'America/Sao_Paulo' });

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

// Cache em memória de notificações já enviadas nesta sessão.
// Chave: "txid|walletName" — permite que o mesmo txid seja notificado
// em perspectivas diferentes (envio na Carteira A, recebimento na Carteira B).
const notifiedTxids = new Set();

// Flag que indica se o subscribeAll inicial já terminou.
// Enquanto false, o ensureGap não é chamado (o subscribeAll faz a varredura completa).
let initialScanDone = false;

// Timestamp da última notificação de bloco enviada (módulo — sobrevive a reconexões)
let _lastBlockNotifAt = 0;

// Buffer de blocos acumulados durante o intervalo
let _pendingBlocks = [];
let _blockFlushTimer = null;

// Referência ao cliente Electrum ativo — usada pelo hot-reload
let _activeElectrum = null;

// Sinaliza que o loop principal deve reconectar (troca de servidor)
let _reconnectRequested = false;
let _reconnectTimer    = null;
// Impede que o polling dispare múltiplas reconexões enquanto uma já está em andamento
let _serverChangePending = false;

// ─── BUFFER DE NOTIFICAÇÕES CONFIRMADAS ──────────────────────────────────────
// Agrupa txs confirmadas pelo critério (bloco, carteira) antes de enviar
// uma única mensagem consolidada ao Telegram.
//
// Chave: "walletName:height"
// Valor: { walletName, height, entries: [{ txid, classification }], timer }
const _confirmedBuffer = new Map();
const CONFIRMED_FLUSH_DELAY = 3000; // ms — aguarda 3s após último item antes de enviar

async function flushConfirmedBuffer(key) {
  const buf = _confirmedBuffer.get(key);
  if (!buf || !buf.entries.length) { _confirmedBuffer.delete(key); return; }
  _confirmedBuffer.delete(key);

  const { walletName, height, entries } = buf;

  // ── Uma única tx → mensagem individual normal ────────────────────────────
  if (entries.length === 1) {
    const { txid, classification } = entries[0];
    const msg = buildTelegramMsg(classification, txid, height, false);
    if (msg) await sendNotification(msg);
    return;
  }

  // ── Múltiplas txs → mensagem consolidada ─────────────────────────────────
  if (notifEnabled('txConfirmed')) {
    const totalReceived = entries
      .filter(e => e.classification.type === 'received')
      .reduce((s, e) => s + (e.classification.valueSat || 0), 0);
    const totalSent = entries
      .filter(e => e.classification.type === 'sent' || e.classification.type === 'sent_with_change')
      .reduce((s, e) => s + (e.classification.sentSats || 0), 0);

    const lines = entries.map(e => {
      const c = e.classification;
      if (c.type === 'received')         return `  📥 Recebimento  <b>+${sats(c.valueSat)} BTC</b>`;
      if (c.type === 'sent')             return `  📤 Envio  <b>-${sats(c.sentSats)} BTC</b>`;
      if (c.type === 'sent_with_change') return `  📤 Envio c/ troco  <b>-${sats(c.sentSats)} BTC</b>`;
      if (c.type === 'consolidation')    return `  🔀 Consolidação  <b>${sats(c.outputSats)} BTC</b>`;
      return `  • ${c.type}`;
    });

    const txidList = entries.map(e => `  🔗 <code>${e.txid}</code>`).join('\n');

    let summary = '';
    if (totalReceived > 0) summary += `💰 Total recebido: <b>+${sats(totalReceived)} BTC</b>\n`;
    if (totalSent > 0)     summary += `💸 Total enviado: <b>-${sats(totalSent)} BTC</b>\n`;

    const msg =
      `✅ <b>${entries.length} transações confirmadas</b>\n` +
      `💼 <b>${walletName}</b>  🧱 Bloco <b>#${height}</b>\n` +
      summary +
      lines.join('\n') + '\n' +
      txidList + '\n' +
      `🕐 ${now()}`;

    await sendNotification(msg);
  }

}

function loadState() {
  // Carrega o state persistido da sessão anterior.
  // O subscribeAll compara o statusHash retornado pelo Electrum Server com o salvo:
  // se iguais, o histórico não mudou offline e getHistory/getBalance são pulados.
  // Se o arquivo não existir ou estiver corrompido, parte do zero.
  try {
    const raw = fs.readFileSync(getCFG().stateFile, 'utf8');
    state = JSON.parse(raw);
    const count = Object.values(state).reduce((n, w) => {
      if (typeof w !== 'object') return n;
      return n + Object.values(w).reduce((m, l) => m + (typeof l === 'object' ? Object.keys(l).length : 0), 0);
    }, 0);
    log.info(`State carregado — ${count} endereços conhecidos (smart boot ativo)`);
  } catch {
    state = {};
    log.info('State não encontrado — varredura completa no boot');
  }
}

function saveState() {
  try {
    // Reconstrói o state ordenando os endereços pelo índice BIP44
    const sorted = {};
    for (const walletName of Object.keys(state).sort()) {
      sorted[walletName] = {};
      for (const label of ['externo', 'change']) {
        const labelData = state[walletName]?.[label];
        if (!labelData) continue;
        // Ordena os endereços pelo índice registrado no addrMap
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
    // Persiste o gapLimit ativo junto com o state para detectar mudanças offline
    sorted._meta = { gapLimit: getCFG().gapLimit };
    fs.writeFileSync(getCFG().stateFile, JSON.stringify(sorted, null, 2));
  } catch(e) { log.error('saveState:', e.message); }
}

// Reconcilia o gapLimit offline: se o gapLimit foi reduzido enquanto o script
// estava desligado, purga do state e de wallet.addresses os endereços vazios
// além do novo cutoff — exatamente como o rebalanceGap faria ao vivo.
// Chamado após loadState() e loadWallets(), antes de conectar ao Electrum Server.
function reconcileGapOnBoot() {
  const currentGap = getCFG().gapLimit;
  const savedGap   = state._meta?.gapLimit ?? currentGap;
  delete state._meta; // remove metadado do state em memória (não é dado de endereço)

  if (currentGap >= savedGap) {
    // Aumento ou igual: o subscribeAll vai derivar os novos endereços naturalmente
    if (currentGap > savedGap)
      log.info(`[boot] gapLimit aumentou offline (${savedGap} → ${currentGap}) — subscribeAll vai derivar os endereços novos`);
    return;
  }

  log.info(`[boot] gapLimit reduzido offline (${savedGap} → ${currentGap}) — purgando endereços excedentes do state`);
  let totalPurged = 0;

  for (const wallet of wallets) {
    if (!wallet.descriptor || wallet.descriptor.startsWith('addr(')) continue;

    for (const chain of [0, 1]) {
      const label    = chain === 0 ? 'ext' : 'chg';
      const stLabel  = chain === 0 ? 'externo' : 'change';
      const addrs    = (wallet.addresses || []).filter(a => a.chain === chain)
                         .sort((a, b) => a.index - b.index);
      if (!addrs.length) continue;

      // Índice do último endereço com histórico
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
        if (hasHistory) continue; // nunca remove endereço com histórico

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
        // Remove do state em memória
        if (state[wallet.name]?.[stLabel])
          delete state[wallet.name][stLabel][a.address];
        purged++;
      }

      if (purged > 0)
        log.info(`  [boot] ${wallet.name} [${label}]: ${purged} endereços purgados (cutoff idx ${cutoff})`);
    }
  }

  if (totalPurged > 0 || true) saveState(); // regrava state.json já com o novo gapLimit
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

// ─── WALLETS & DERIVAÇÃO ──────────────────────────────────────────────────────
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

  // Índice mais alto já derivado para este chain
  const existing = (wallet.addresses || []).filter(a => a.chain === chain);
  const lastIdx  = existing.length ? Math.max(...existing.map(a => a.index)) : -1;
  if (lastIdx >= needed) return [];

  const newEntries = [];
  for (let i = lastIdx + 1; i <= Math.min(needed, cfg.maxIndex); i++) {
    // Evita derivar índice já presente (proteção contra chamadas concorrentes)
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
      log.info('wallets.json criado — adicione carteiras pelo painel');
      wallets = [];
    }
  } catch { wallets = []; }

  if (!wallets.length) {
    log.warn('Nenhuma carteira configurada — adicione descritores pelo painel');
  }

  addrMap.clear(); shMap.clear();

  for (const wallet of wallets) {
    if (!wallet.descriptor) continue;
    wallet.addresses = wallet.addresses || [];

    const hrp = walletHrp(wallet);
    const startIdx = wallet.startIndex ?? 0;

    // Deriva e registra apenas os endereços já conhecidos (de boots anteriores).
    // O subscribeAll vai derivar mais conforme necessário consultando o Electrum Server.
    const isSingleAddress = wallet.descriptor.startsWith('addr(');

    const chains = isSingleAddress ? [0] : [0, 1];

    for (const chain of chains) {
      const desc = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;

      // Garante que cada entry tem chain e index preenchidos
      for (const entry of wallet.addresses.filter(a => a.chain === chain)) {
        const sh = entry.scriptHash || (entry.scriptHex ? scriptToScriptHash(entry.scriptHex) : null);
        if (sh) registerAddress({ ...entry, scriptHash: sh }, wallet, chain, entry.index ?? 0);
      }

      // Deriva ao menos os primeiros gapLimit endereços para ter ponto de partida.
      // Para addr() não há derivação real — deriva apenas o índice 0 e para.
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
    log.info(`  ${wallet.name}: ${ext} ext, ${chg} chg pré-derivados`);
  }
}


// ─── NOTIFICAÇÕES ────────────────────────────────────────────────────────────
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
  // Converte tags HTML do Telegram para Markdown do ntfy
  const clean = text
    .replace(/<b>(.*?)<\/b>/gi,                        '**$1**')   // negrito
    .replace(/<i>(.*?)<\/i>/gi,                        '*$1*')     // itálico
    .replace(/<code>(.*?)<\/code>/gi,                  '`$1`')     // inline code
    .replace(/<a\b[^>]*href="([^"]*)"[^>]*>(.*?)<\/a>/gi, '[$2]($1)') // link
    .replace(/<[^>]+>/g, '');                                       // tags restantes
  const body  = Buffer.from(clean, 'utf8');
  const u     = new URL(url);
  const headers = {
    'Content-Type':   'text/plain',
    'Content-Length': body.length,
    'Markdown':       'yes',
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return new Promise(resolve => {
    const req = https.request({
      hostname: u.hostname,
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

// ─── CLASSIFICAÇÃO DE TRANSAÇÕES ─────────────────────────────────────────────
//
// Analisa uma tx completa e determina:
//   - se algum vin pertence ao nosso state → saída/consolidação
//   - se nenhum vin pertence ao nosso state → recebimento externo
//
// Tipos:
//   'received'         — origem externa, valor entrou num endereço nosso
//   'sent'             — saída sem troco para endereços nossos
//   'sent_with_change' — saída com troco voltando para endereço nosso
//   'consolidation'    — toda saída vai para endereços nossos
//
// electrum é opcional: se fornecido, usa como fallback para buscar prevouts
// quando o servidor não os inclui no verbose tx (Electrum Server < 1.9).

async function classifyTx(txData, walletName, network, electrum) {
  const vins  = txData.vin  || [];
  const vouts = txData.vout || [];

  // ── Mapeia cada vout ao seu scriptHash ──────────────────────────────────────
  const voutScriptHashes = vouts.map(out => {
    const hex = out.scriptPubKey?.hex || '';
    return hex ? scriptHexToScriptHash(hex) : null;
  });

  // ── Detecta inputs nossos ──────────────────────────────────────────────────
  // Estratégia 1: vin.prevout.scriptPubKey.hex (Electrum Server >= 1.9, verbose=true)
  // Estratégia 2: fallback — busca a tx anterior e pega o vout[vin.vout]
  let myInputSats = 0;
  const inputAddrs = new Set();

  for (const vin of vins) {
    if (vin.coinbase) continue; // tx coinbase não tem prevout real

    let prevScript = vin.prevout?.scriptPubKey?.hex || '';
    let prevValue  = vin.prevout?.value ?? null;

    // Fallback: busca a tx do input para obter scriptPubKey e/ou value quando
    // o Electrum Server não inclui prevout completo (comum em Signet/Testnet mempool)
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
    // Só conta como input nosso se pertencer à MESMA carteira sendo analisada
    const prevEntry = (shMap.get(prevSh) || []).find(e => e.wallet.name === walletName);
    const addr      = prevEntry?.address;
    if (addr && addrMap.has(addr + '|' + walletName)) {
      const val = prevValue ?? 0;
      myInputSats += Math.round(val * 1e8);
      inputAddrs.add(addr);
    }
  }

  const isOutgoing = inputAddrs.size > 0;

  // ── Classifica vouts ───────────────────────────────────────────────────────
  let myOutputSats    = 0;
  let extOutputSats   = 0;
  const changeOutputs = []; // vouts que voltaram para endereços nossos
  const extOutputs    = []; // vouts para endereços externos

  for (let i = 0; i < vouts.length; i++) {
    const out    = vouts[i];
    const sh      = voutScriptHashes[i];
    const valSat  = Math.round((out.value || 0) * 1e8);

    // Só considera "endereço nosso" se pertencer à MESMA carteira que está
    // sendo analisada — evita classificar transferência entre carteiras
    // monitoradas como consolidação interna.
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

  // ── RECEBIMENTO PURO ────────────────────────────────────────────────────────
  if (!isOutgoing) {
    if (!myOutputSats) return null; // nenhum vout nosso — não deveria ocorrer
    return {
      type:         'received',
      walletName,
      network,
      valueSat:     myOutputSats,
      destinations: changeOutputs,
    };
  }

  // ── SAÍDA ───────────────────────────────────────────────────────────────────
  const hasExternalOutput = extOutputs.length > 0;
  const hasChangeOutput   = changeOutputs.length > 0;

  if (!hasExternalOutput) {
    // Toda saída voltou para endereços nossos → consolidação interna
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
    // Enviou para fora com troco voltando
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

  // Enviou tudo para fora, sem troco
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

// ─── MENSAGENS TELEGRAM ───────────────────────────────────────────────────────
function buildTelegramMsg(classification, txid, height, isPending) {
  const { type, walletName, network } = classification;
  const _url  = mempoolLink(txid);
  const link  = _url ? `\n<a href="${_url}">Ver no ${mempoolLinkLabel()}</a>` : '';
  const status  = isPending ? '⏳ Aguardando confirmação' : `🧱 Bloco #${height}`;
  const ts_line = `🕐 ${now()}`;

  if (type === 'received') {
    const total = classification.valueSat;
    const dests = classification.destinations.map(d =>
      `  📍 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`
    ).join('\n');
    return `📥 <b>Recebimento</b>
💼 <b>${walletName}</b>
💰 Total recebido: <b>${sats(total)} BTC</b>
${dests}
🔗 <code>${txid}</code>
${status}
${ts_line}${link}`;
  }

  if (type === 'sent') {
    const dests = classification.destinations.map(d =>
      `  📤 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`
    ).join('\n');
    return `📤 <b>Envio</b>
💼 <b>${walletName}</b>
💸 Total enviado: <b>${sats(classification.sentSats)} BTC</b>
⛽ Taxa: <b>${sats(classification.feeSats)} BTC</b>
${dests}
🔗 <code>${txid}</code>
${status}
${ts_line}${link}`;
  }

  if (type === 'sent_with_change') {
    const dests = classification.destinations.map(d =>
      `  📤 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`
    ).join('\n');
    const changes = classification.changeOutputs.map(d =>
      `  🔄 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`
    ).join('\n');
    return `📤 <b>Envio com troco</b>
💼 <b>${walletName}</b>
💸 Enviado: <b>${sats(classification.sentSats)} BTC</b>
🔄 Troco: <b>${sats(classification.changeSats)} BTC</b>
⛽ Taxa: <b>${sats(classification.feeSats)} BTC</b>
Destinos externos:
${dests}
Troco (endereços seus):
${changes}
🔗 <code>${txid}</code>
${status}
${ts_line}${link}`;
  }

  if (type === 'consolidation') {
    const dests = classification.destinations.map(d =>
      `  🔀 <code>${d.address}</code>  <b>${sats(d.valueSat)} BTC</b>`
    ).join('\n');
    return `🔀 <b>Consolidação interna</b>
💼 <b>${walletName}</b>
💰 Valor consolidado: <b>${sats(classification.outputSats)} BTC</b>
${dests}
🔗 <code>${txid}</code>
${status}
${ts_line}${link}`;
  }

  return null;
}

function msgStartup(addrCount, gapLimit) {
  const _e = getCFG().electrum;
  return `🚀 <b>BitTrack v5 iniciado</b>
🔌 Electrum Server: <code>${_e.host}:${_e.port}</code>
👀 Endereços: <b>${addrCount}</b>
🔍 Gap limit: <b>${gapLimit}</b>
⚡ Modo: <b>scripthash.subscribe</b>
🕐 ${now()}`;
}

// ─── ELECTRUM CLIENT ──────────────────────────────────────────────────────────
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
      if (!host) { reject(new Error('host não configurado — edite electrum.host no config.json ou pelo painel')); return; }
      log.info(`  [connect] tentando ${host}:${port} TLS=${useTLS}`);

      // Garante que resolve/reject só sejam chamados uma vez
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
      // 'close' durante o connect (ex: socket.destroy() pelo hot-reload) rejeita a Promise
      // imediatamente em vez de aguardar o timeout de 15s.
      // _flushPending rejeita também qualquer call() em andamento (subscribe/getHistory etc.)
      // para não ficar aguardando o timeout de 20s após o socket ser destruído.
      this.socket.on('close',   ()    => { this.connected = false; log.warn('Electrum: conexão encerrada'); this._flushPending(new Error('conexão encerrada')); _reject(new Error('conexão encerrada')); });
      this.socket.on('timeout', ()    => { this.socket.destroy(); _reject(new Error('conexão timeout')); });
    });
  }

  // Rejeita imediatamente todas as Promises de call() em andamento.
  // Chamado ao fechar o socket para não aguardar o timeout de 20s de cada request.
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
      log.warn('Electrum: 90s sem dados — forçando reconexão');
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
      if (!this.connected) return reject(new Error('não conectado'));
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

// ─── UTILITÁRIO: scriptHex → scriptHash (SHA256 reverso) ─────────────────────
function scriptHexToScriptHash(scriptHex) {
  return createHash('sha256')
    .update(Buffer.from(scriptHex, 'hex'))
    .digest()
    .reverse()
    .toString('hex');
}

// ─── CALCULA VALOR RECEBIDO NUMA TX (vouts que pertencem ao nosso scriptHash) ─
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

// ─── PROCESSA MUDANÇA DE SCRIPTHASH ──────────────────────────────────────────
async function processChange(electrum, scriptHash, newStatusHash) {
  const entries = shMap.get(scriptHash);
  if (!entries || !entries.length) return;

  // Busca histórico uma única vez — é o mesmo para todas as wallets
  const history = await electrum.getHistory(scriptHash).catch(() => []);
  const confirmedTxids = history.filter(h => h.height > 0).map(h => h.tx_hash);
  const mempoolTxids   = history.filter(h => h.height <= 0).map(h => h.tx_hash);

  // Busca saldo uma única vez
  const balance  = history.length
    ? await electrum.getBalance(scriptHash).catch(() => ({ confirmed: 0, unconfirmed: 0 }))
    : { confirmed: 0, unconfirmed: 0 };
  const confirmedSat  = balance.confirmed  || 0;
  const unconfirmedSat= balance.unconfirmed|| 0;
  const totalSat = confirmedSat + unconfirmedSat;

  // Processa cada wallet que monitora este scriptHash independentemente
  for (const { address, wallet, chain, index } of entries) {
    const network = wallet.network || 'mainnet';
    const prev    = getAddrState(address, wallet.name);

    // Ignora se status não mudou e já foi inicializado
    if (prev.statusHash === newStatusHash && prev.balanceSat !== null) continue;

    if (!history.length) {
      setAddrState(address, { balanceSat: 0, txids: [], mempoolTxids: [], statusHash: newStatusHash }, wallet.name);
      continue;
    }

    const prevConfirmed = prev.txids        || [];
    const prevMempool   = prev.mempoolTxids || [];

    // ── Sincronização silenciosa ──
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
        log.info(`  Sync inicial: ${address.slice(0,20)}… ${confirmedTxids.length} txs, saldo ${sats(confirmedSat)} BTC (+${sats(unconfirmedSat)} mempool)`);
      else
        log.info(`  Catch-up: ${address.slice(0,20)}… ${confirmedTxids.length} txs (offline gap, sem notificação)`);

      // ── Catch-up do txhistory ─────────────────────────────────────────────
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
              log.info(`  [txhistory] ${txid.slice(0,16)}… promovido mempool→bloco #${he.height}`);
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

    // ── Sincronização subsequente — só notifica mudanças reais ──
    let hasActivity = false;

    // ── Mempool: uma mensagem por tx (sem agrupamento) ─────────────────────
    async function notifyMempool(txid) {
      const notifKey = `${txid}|${wallet.name}`;
      if (notifiedTxids.has(notifKey)) return;
      notifiedTxids.add(notifKey);
      let txData;
      try { txData = await electrum.getTransaction(txid); }
      catch(e) { log.warn(`  transaction.get ${txid.slice(0,16)}…: ${e.message}`); return; }
      const classification = await classifyTx(txData, wallet.name, network, electrum);
      if (!classification) { log.warn(`  classifyTx: nenhum vout nosso em ${txid.slice(0,16)}…`); return; }

      // Registra no histórico (mempool=true)
      const he = history.find(h => h.tx_hash === txid);
      appendTxHistory(classification, txid, null, true, he);

      if (!notifEnabled('mempoolPending')) {
        log.info(`  [filtro] mempool tx ignorada (notif desligada): ${txid.slice(0,16)}…`);
        return;
      }
      const msg = buildTelegramMsg(classification, txid, null, true);
      if (!msg) return;
      log.info(`📥 [${classification.type}] ${address.slice(0,20)}… ${txid.slice(0,16)}…`);
      await sendNotification(msg);
    }

    // ── Confirmadas: acumula no buffer por (bloco, carteira) ─────────────────
    async function bufferConfirmed(txid, height) {
      // Chave específica para confirmação — evita que dois endereços da mesma
      // carteira (ex: saída + troco) processem o mesmo txid duas vezes
      const confirmedKey = `confirmed:${txid}|${wallet.name}`;
      if (notifiedTxids.has(confirmedKey)) return;
      notifiedTxids.add(confirmedKey);
      let txData;
      try { txData = await electrum.getTransaction(txid); }
      catch(e) { log.warn(`  transaction.get ${txid.slice(0,16)}…: ${e.message}`); return; }
      const classification = await classifyTx(txData, wallet.name, network, electrum);
      if (!classification) { log.warn(`  classifyTx: nenhum vout nosso em ${txid.slice(0,16)}…`); return; }

      // Registra/atualiza no histórico (confirmada)
      const he = history.find(h => h.tx_hash === txid);
      appendTxHistory(classification, txid, height, false, he);

      if (!notifEnabled('txConfirmed')) {
        log.info(`  [filtro] tx confirmada ignorada (notif desligada): ${txid.slice(0,16)}…`);
        return;
      }
      log.info(`✅ [${classification.type}] ${address.slice(0,20)}… ${txid.slice(0,16)}… → buffer bloco #${height}`);

      const key = `${wallet.name}:${height}`;
      const buf = _confirmedBuffer.get(key) || { walletName: wallet.name, height, entries: [], timer: null };
      buf.entries.push({ txid, classification });

      // Reinicia debounce — envia 3s após o último item adicionado
      clearTimeout(buf.timer);
      buf.timer = setTimeout(() => flushConfirmedBuffer(key), CONFIRMED_FLUSH_DELAY);
      _confirmedBuffer.set(key, buf);
    }

    for (const txid of mempoolTxids) {
      if (prevMempool.includes(txid) || prevConfirmed.includes(txid)) continue;
      hasActivity = true;
      await notifyMempool(txid);
    }

    // ── Detecta dropped/RBF ao vivo ──────────────────────────────────────────
    // Txids que estavam no mempool anterior mas desapareceram sem confirmar
    for (const txid of prevMempool) {
      if (mempoolTxids.includes(txid) || confirmedTxids.includes(txid)) continue;
      // Sumiu da mempool sem confirmar → dropped ou substituído por RBF
      const cur = readTxHistory();
      const rec = cur[wallet.name]?.txids?.[txid];
      if (rec && rec.mempool) {
        rec.mempool   = false;
        rec.dropped   = true;
        rec.droppedAt = Date.now();
        writeTxHistory(cur);
        log.warn(`  [RBF/drop] ${txid.slice(0,16)}… removido do mempool sem confirmar (${wallet.name})`);
        if (notifEnabled('mempoolPending')) {
          await sendNotification(
            `⚠️ <b>Transação removida do mempool</b>\n` +
            `💼 <b>${wallet.name}</b>\n` +
            `🔗 <code>${txid}</code>\n` +
            `ℹ️ Pode ter sido substituída por taxa maior (RBF) ou expirado\n` +
            `🕐 ${now()}`
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

// ─── SUBSCRIBE TODOS OS ENDEREÇOS ─────────────────────────────────────────────
// Erro especial usado para abortar o subscribeAll de forma controlada.
// O catch do loop principal reconhece esse tipo e trata como reconexão intencional.
class AbortScanError extends Error {
  constructor() { super('varredura interrompida — troca de servidor'); this.isAbort = true; }
}

async function subscribeAll(electrum) {
  // Verifica se deve abortar — lança AbortScanError se _reconnectRequested estiver ativo
  // ou se o socket foi destruído (electrum.connected = false após hot-reload).
  function checkAbort() {
    if (_reconnectRequested || !electrum.connected) throw new AbortScanError();
  }

  electrum.on('blockchain.scripthash.subscribe', async ([sh, statusHash]) => {
    try { await processChange(electrum, sh, statusHash); }
    catch(e) { log.error('processChange:', e.message); }
  });

  electrum.on('blockchain.headers.subscribe', async ([header]) => {
    const height = header.height;
    log.info(`🧱 Novo bloco #${height}`);

    const everyBlockOn = notifEnabled('everyBlock');
    log.info(`  [bloco] everyBlock=${everyBlockOn}`);
    if (!everyBlockOn) return;

    const intervalMin = getNotifValue('blockIntervalMin', 0);

    // Acumula o bloco no buffer
    _pendingBlocks.push(height);

    if (intervalMin === 0) {
      // Sem intervalo — envia imediatamente, um por um
      _pendingBlocks = [];
      log.info(`  [bloco] enviando notificação para bloco #${height}`);
      await sendNotification(
        `⛏️ <b>Novo bloco minerado</b>\n` +
        `🧱 Altura: <b>#${height}</b>\n` +
        `🕐 ${now()}`
      ).catch(e => log.warn(`  [bloco] sendTelegram erro: ${e.message}`));
      return;
    }

    // Com intervalo — acumula e envia ao final do período
    const now_ms  = Date.now();
    const elapsed = now_ms - _lastBlockNotifAt;
    const needed  = intervalMin * 60 * 1000;

    if (elapsed >= needed) {
      // Intervalo expirou — flush imediato
      clearTimeout(_blockFlushTimer);
      _blockFlushTimer = null;
      const blocks = [..._pendingBlocks];
      _pendingBlocks = [];
      _lastBlockNotifAt = now_ms;
      await flushBlocks(blocks);
    } else if (!_blockFlushTimer) {
      // Agenda flush para quando o intervalo expirar
      const remaining = needed - elapsed;
      log.info(`  [bloco] acumulando — flush em ${Math.round(remaining/1000)}s`);
      _blockFlushTimer = setTimeout(async () => {
        _blockFlushTimer = null;
        const blocks = [..._pendingBlocks];
        _pendingBlocks = [];
        _lastBlockNotifAt = Date.now();
        await flushBlocks(blocks);
      }, remaining);
    } else {
      log.info(`  [bloco] acumulando bloco #${height} (${_pendingBlocks.length} no buffer)`);
    }
  });

  async function flushBlocks(blocks) {
    if (!blocks.length) return;
    if (blocks.length === 1) {
      log.info(`  [bloco] enviando notificação para bloco #${blocks[0]}`);
      await sendNotification(
        `⛏️ <b>Novo bloco minerado</b>\n` +
        `🧱 Altura: <b>#${blocks[0]}</b>\n` +
        `🕐 ${now()}`
      ).catch(e => log.warn(`  [bloco] sendTelegram erro: ${e.message}`));
    } else {
      const list = blocks.map(h => `#${h}`).join(', ');
      log.info(`  [bloco] enviando ${blocks.length} blocos acumulados: ${list}`);
      await sendNotification(
        `⛏️ <b>${blocks.length} blocos minerados</b>\n` +
        `🧱 <b>${list}</b>\n` +
        `🕐 ${now()}`
      ).catch(e => log.warn(`  [bloco] sendTelegram erro: ${e.message}`));
    }
  }
  try {
    const tip = await electrum.call('blockchain.headers.subscribe', []);
    log.info(`Bloco atual: #${tip.height || tip.block_height || '?'}`);
  } catch {}

  let totalOk = 0;
  initialScanDone = false; // reseta para cada ciclo de conexão

  for (const wallet of wallets) {
    if (!wallet.descriptor) continue;
    const hrp      = walletHrp(wallet);
    const startIdx = wallet.startIndex ?? 0;

    const isSingleAddress = wallet.descriptor.startsWith('addr(');

    const chains = isSingleAddress ? [0] : [0, 1];

    for (const chain of chains) {

      const desc  = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;
      const label = chain === 0 ? 'ext' : 'chg';

      // Varredura BIP44: avança sequencialmente, para só quando o Electrum Server
      // confirmar gapLimit endereços vazios consecutivos.
      let consecutiveEmpty = 0;
      let i = startIdx;
      let lastUsed = startIdx - 1;

      while (consecutiveEmpty < getCFG().gapLimit && i <= getCFG().maxIndex) {
        checkAbort(); // ← aborta imediatamente se servidor foi trocado

        // Deriva o endereço se ainda não existir
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

          // ── Smart boot: compara statusHash com o salvo na sessão anterior ──
          // hashUnchanged: statusHash igual ao salvo → histórico intacto offline
          // knownEmpty:    statusHash null + balanceSat 0 → continua vazio
          // Ambos os casos pulam getHistory/getBalance.
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
            checkAbort(); // ← verifica após cada sleep
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
          // Socket destruído durante o await subscribe/getHistory → trata como abort
          if (!electrum.connected || _reconnectRequested) throw new AbortScanError();
          log.error(`  subscribe [${label}/${i}] ${entry.address.slice(0,16)}…: ${e.message}`);
          consecutiveEmpty++;
        }

        await sleep(getCFG().subscribeDelayMs);
        checkAbort(); // ← verifica após cada sleep
        i++;

        // addr() é um endereço fixo — não há derivação, basta processar uma vez
        if (isSingleAddress) break;
      }

      const total = wallet.addresses.filter(a => a.chain === chain).length;
      log.info(`  ${wallet.name} [${label}]: ${total} endereços, último usado idx ${lastUsed}`);
    }
  }

  initialScanDone = true;
  log.ok(`${totalOk} scripthashes subscritos — ${shMap.size} scriptHashes / ${addrMap.size} entradas monitoradas ⚡`);
}


// ─── PREÇO BTC/USD ────────────────────────────────────────────────────────────
let _priceCache = { usd: null, updatedAt: null };

// PRICE_APIS é uma função para que a currency seja lida do config no momento
// da chamada — permite trocar a moeda sem reiniciar o monitor.
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
      log.warn(`[config] API inválida: ${id}`);
    }
  });

  if (!list.length) {
    log.warn('  [preço] nenhuma API configurada');
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
        log.info(`  [preço] ${api.name} → ${fmtPrice(price)}`);
        _priceCache = { usd: price, updatedAt: Date.now() };
        writeRuntime({ price: _priceCache });
        appendPriceHistory(price);
        return price;
      }
    } catch(e) {
      log.warn(`  [preço] ${api.name} falhou: ${e.message}`);
    }
  }
  log.warn('  [preço] todas as APIs falharam');
  return null;
}


// ─── RECONCILIA MEMPOOL→CONFIRMADO/DROPPED NO TXHISTORY ──────────────────────
// Varre o txhistory.json procurando entradas com mempool:true e:
//   1. Se a tx foi confirmada → promove (mempool=false, preenche height/ts)
//   2. Se a tx foi dropada ou substituída por RBF → marca dropped=true
//      (não remove, pois é informação histórica útil)
// Detecção de dropped: a tx não aparece mais no histórico do Electrum de nenhum
// endereço da carteira — nem como confirmada nem como mempool.
// Roda uma vez após o subscribeAll terminar.
async function reconcileMempoolTxHistory(electrum) {
  const h = readTxHistory();
  let promoted = 0, dropped = 0;

  for (const [walletName, wData] of Object.entries(h)) {
    if (!wData?.txids) continue;

    // Pré-carrega o histórico completo de todos os endereços desta carteira
    // para poder verificar rapidamente se um txid ainda existe no Electrum.
    // Cache: scriptHash → Set de txids presentes no Electrum
    const electrumTxids = new Map(); // scriptHash → Set<txid>

    for (const [txid, tx] of Object.entries(wData.txids)) {
      if (!tx.mempool) continue; // só processa os ainda como mempool

      try {
        // ── Passo 1: a tx ainda existe no Electrum? ─────────────────────────
        const txData = await electrum.getTransaction(txid).catch(() => null);

        if (!txData) {
          // getTransaction falhou — tx pode ter sido dropada do mempool
          // Verifica se aparece no histórico de algum endereço da carteira
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
          // Ainda na mempool — sem ação
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
            // Já temos o set mas precisamos do height — refaz getHistory só se necessário
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
        log.info(`  [reconcile] ${txid.slice(0,16)}… promovido mempool→${height ? 'bloco #'+height : 'confirmado'} (${walletName})`);

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
    log.info('[reconcile] nenhuma tx pendente na mempool para reconciliar');
  }
}

async function run() {
  log.info('╔═════════════════════════════════════════╗');
  log.info('║  BitTrack Monitor v5 — Electrum Server  ║');
  log.info('║     scripthash.subscribe + Telegram     ║');
  log.info('╚═════════════════════════════════════════╝');

  loadState();
  loadWallets();
  reconcileGapOnBoot(); // reconcilia redução de gapLimit que ocorreu offline

  // Ativa o lock imediatamente — painel fica bloqueado até o boot estar completo
  writeRuntime({ lock: { active: true, msg: 'iniciando...', since: Date.now(), timeoutAt: null } });
  log.info('boot iniciado — runtime lock ativado');

  // ── Detecta txhistory ausente/vazio e força ressincronização completa ─────
  // Se o txhistory.json não existe ou está vazio, invalida o statusHash de
  // todos os endereços com histórico no state — isso força o processChange
  // a rodar o catch-up completo em cada um, reconstruindo o txhistory do zero.
  // Endereços sem histórico (balanceSat=0, txids=[]) são preservados.
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
          // Só invalida endereços que têm histórico — não toca endereços vazios
          if ((addrData.txids?.length || 0) > 0 || (addrData.mempoolTxids?.length || 0) > 0) {
            addrData.statusHash = null; // força reprocessamento no subscribeAll
            invalidated++;
          }
        }
      }
    }
    if (invalidated > 0) {
      log.info(`[boot] txhistory ausente — ${invalidated} endereço(s) com histórico marcados para ressincronização`);
    }
  }

  const _initCfg = getCFG();
  log.info(`Endereços: ${addrMap.size} | Gap limit: ${_initCfg.gapLimit}`);
  log.info(`Electrum Server: ${_initCfg.electrum.host}:${_initCfg.electrum.port} ${_initCfg.electrum.tls ? '(TLS)' : '(TCP)'}`);

  if (!_initCfg.telegram.enabled || !_initCfg.telegram.token || !_initCfg.telegram.chatId)
    log.warn('Telegram não configurado ou desativado');
  if (_initCfg.ntfy?.enabled && !_initCfg.ntfy?.url)
    log.warn('ntfy ativado mas URL não configurada');

  // ── Monitor de preço BTC/USD ──────────────────────────────────────────────
  // Restaura referência salva no config.json para não perder ponto de
  // comparação entre reinicializações do monitor.
  // Referência de preço — sempre parte de null no boot.
  // O primeiro checkPrice vai buscar o preço atual e definir a referência com
  // base em prioridade:
  //   1. priceReference do config (se dentro de ±20% do preço atual)
  //   2. Preço atual buscado na API
  // O runtime.json não é mais usado como ref inicial — pode estar desatualizado.
  let _lastNotifiedPrice = null;

  // Intervalo dinâmico — relido do config a cada ciclo
  // Mutex: garante que só uma checagem roda por vez
  let _priceTimer   = null;
  let _priceRunning = false;
  let _threshWarnLogged = false; // avisa só uma vez sobre limiar ajustado

  function schedulePriceCheck(immediate = false) {
    const interval = immediate ? 0 : getCFG().priceCheckIntervalSec * 1000;
    _priceTimer = setTimeout(async () => {
      if (_priceRunning) { schedulePriceCheck(); return; } // já rodando — adia
      _priceRunning = true;
      try { await checkPrice(); } catch(e) { log.warn(`checkPrice: ${e.message}`); }
      _priceRunning = false;
      schedulePriceCheck();
    }, interval);
  }

  // Rastreia o valor de priceReference já aplicado — evita reaplicar a cada checagem
  let _appliedCfgRef = null;

  // Aplica priceReference do config se for um valor novo (diferente do último aplicado).
  // Valida ±priceRefMaxDeviationPct% em relação ao preço atual.
  function applyPriceReference(currentPrice) {
    const cfgRef = getNotifValue('priceReference', null);
    if (!cfgRef || cfgRef <= 0) return null; // null = sem referência manual

    // Já foi aplicado anteriormente — não reaplicar
    if (cfgRef === _appliedCfgRef) return null;

    const maxDev = (getCFG().priceRefMaxDeviationPct || 20) / 100;
    const lo = currentPrice * (1 - maxDev);
    const hi = currentPrice * (1 + maxDev);
    if (cfgRef < lo || cfgRef > hi) {
      log.warn(`  [preço] priceReference=${fmtPrice(cfgRef)} fora de ±${getCFG().priceRefMaxDeviationPct||20}% (${fmtPrice(Math.round(lo))}–${fmtPrice(Math.round(hi))}) — ignorado`);
      _appliedCfgRef = cfgRef; // marca como processado para não logar a cada ciclo
      return null;
    }

    _appliedCfgRef = cfgRef;
    log.info(`  [preço] referência manual aplicada: ${fmtPrice(cfgRef)}`);
    return cfgRef;
  }

  async function checkPrice() {
    const enabled   = notifEnabled('priceChange');
    const rawPct = getNotifValue('priceThresholdPct', 1);
    try {
      const price = await fetchPrice();
      if (!price) return;

      // Converte % → USD e aplica faixa mínima/máxima
      const _cfgLimits = getCFG();
      const minPct     = _cfgLimits.priceThresholdMinPct || 1;
      const maxPct     = _cfgLimits.priceThresholdMaxPct || 50;
      const clampedPct = Math.min(Math.max(rawPct, minPct), maxPct);
      if (clampedPct !== rawPct) {
        if (!_threshWarnLogged) {
          log.warn(`  [preço] priceThresholdPct ${rawPct}% fora da faixa — corrigido para ${clampedPct}% no config`);
          _threshWarnLogged = true;
          saveThresholdPct(clampedPct); // corrige no config.json
        }
      } else {
        _threshWarnLogged = false;
      }
      const threshold = Math.ceil(price * clampedPct / 100);
      log.info(`  [preço] limiar: ${clampedPct}% = ${fmtPrice(threshold)}`);

      // Primeira execução — define referência e persiste no config
      if (_lastNotifiedPrice === null) {
        const manualRef = applyPriceReference(price);
        _lastNotifiedPrice = manualRef !== null ? manualRef : price;
        savePriceReference(_lastNotifiedPrice); // grava no config mesmo antes da 1ª notificação
        log.info(`  [preço] referência inicial: ${fmtPrice(_lastNotifiedPrice)} | limiar: ${clampedPct}% (${fmtPrice(threshold)}) | notif=${enabled}`);
        return;
      }

      // Verifica se há nova referência manual no config (valor diferente do último aplicado)
      const manualRef = applyPriceReference(price);
      if (manualRef !== null) {
        _lastNotifiedPrice = manualRef;
        log.info(`  [preço] referência manual definida: ${fmtPrice(_lastNotifiedPrice)}`);
      }

      const delta = Math.abs(price - _lastNotifiedPrice);
      log.info(`  [preço] atual=${fmtPrice(price)} ref=${fmtPrice(_lastNotifiedPrice)} Δ=${fmtPrice(Math.round(delta))} limiar=${clampedPct}%(${fmtPrice(threshold)}) notif=${enabled}`);

      if (enabled && delta >= threshold) {
        const dir  = price > _lastNotifiedPrice ? '📈' : '📉';
        const sign = price > _lastNotifiedPrice ? '+' : '-';
        await sendNotification(
          `${dir} <b>Variação de preço BTC</b>\n` +
          `💵 Preço atual: <b>${fmtPrice(price)}</b>\n` +
          `🔀 Variação: <b>${sign}${fmtPrice(Math.round(delta))}</b> <i>(${sign}${(delta / _lastNotifiedPrice * 100).toFixed(2)}%)</i>\n` +
          `📌 Referência: <b>${fmtPrice(Math.round(_lastNotifiedPrice))}</b>  |  Limiar: <b>${clampedPct}%</b>\n` +
          `🕐 ${now()}`
        );
        log.info(`${dir} BTC ${fmtPrice(price)} (Δ${sign}${fmtPrice(Math.round(delta))}) → Telegram`);
        // Atualiza ref após notificar — próxima notificação parte do preço atual
        _lastNotifiedPrice = price;
        _appliedCfgRef     = price; // evita que o config reaaplique o valor antigo
        savePriceReference(price);  // persiste no config.json
      } else if (!enabled) {
        // Notif desligada — acompanha o preço para não acumular delta ao religar
        _lastNotifiedPrice = price;
      }
      // Notif ligada mas delta abaixo do limiar — ref não muda, delta continua acumulando
    } catch(e) { log.warn(`checkPrice: ${e.message}`); }
  }

  log.info(`  [preço] loop iniciado — intervalo: ${getCFG().priceCheckIntervalSec}s`);
  schedulePriceCheck(true); // roda imediatamente e agenda os próximos
  // ─────────────────────────────────────────────────────────────────────────

  while (true) {
    const cfg     = getCFG();
    const electrum = new ElectrumClient();
    _activeElectrum = electrum;
    // Reseta flags de reconexão no início de cada tentativa — qualquer sinalização
    // que chegue DURANTE o connect() será processada na próxima iteração.
    _reconnectRequested  = false;
    _serverChangePending = false;

    try {
      await electrum.connect();

      // Handshake
      const ver = await electrum.call('server.version', ['BitTrack/5.0', '1.4']);
      log.info(`Servidor: ${Array.isArray(ver) ? ver.join(' / ') : ver}`);

      await sendNotification(msgStartup(addrMap.size, getCFG().gapLimit));

      await subscribeAll(electrum);

      // Reconcilia txs que estavam na mempool e foram confirmadas enquanto offline
      await reconcileMempoolTxHistory(electrum).catch(e =>
        log.warn(`[reconcile] erro: ${e.message}`)
      );

      // Busca fees inicial logo após conexão
      await fetchAndSaveFees(electrum).catch(() => {});

      // Boot completo — só agora libera o painel
      if (!_reconnectRequested) {
        writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
        log.info('boot concluído — runtime lock liberado');
      }

      // Keepalive + atualização de fees a cada ping
      const pingTimer = setInterval(async () => {
        if (!electrum.connected) { clearInterval(pingTimer); return; }
        try {
          await electrum.ping();
          await fetchAndSaveFees(electrum).catch(() => {});
        } catch(e) {
          log.warn(`  [ping] falhou (${e.message}) — forçando reconexão`);
          electrum.disconnect();
        }
      }, cfg.pingInterval);

      // Aguarda desconexão ou pedido de reconexão por troca de servidor
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
      // AbortScanError → interrupção intencional do subscribeAll — não loga nem libera lock.
      // "conexão encerrada" com _reconnectRequested → hot-reload destruiu o socket
      // intencionalmente para forçar reconexão — também não libera lock aqui.
      const intentional = e.isAbort || (_reconnectRequested && e.message === 'conexão encerrada');
      if (!intentional) {
        // Falha real de conexão (timeout, recusa, host inválido) — libera o lock
        // imediatamente com o erro para o painel exibir sem esperar o reconnectDelay.
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
      log.warn(`Electrum não configurado — aguardando 30s. Configure electrum.host no painel ou config.json`);
      // Espera 30s mas ainda permite interrupção por troca de servidor
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
      // Troca de servidor detectada — pequena pausa de 300ms e reconecta
      log.info(`Reconectando ao novo servidor em 300ms…`);
      await sleep(300);
    } else {
      // Falha de rede — sempre espera os 10s completos (não interruptível por polling)
      const delay = _cfg2.reconnectDelay || 10000;
      log.info(`Reconectando em ${delay / 1000}s…`);
      await new Promise(resolve => {
        _reconnectTimer = setTimeout(() => { _reconnectTimer = null; resolve(); }, delay);
        // Ainda permite interrupção se houver troca de servidor durante o wait
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

// ─── HOT-RELOAD ───────────────────────────────────────────────────────────────
// Detecta mudanças em config.json e wallets.json sem reiniciar o processo.
//
// config.json:
//   - Telegram / notificações / gapLimit / maxIndex → aplica em tempo real
//     (já funciona porque getNotifications() e getCFG() leem do disco)
//   - host/porta/TLS mudou → sinaliza reconexão ao novo servidor
//
// wallets.json:
//   - Novo descritor → subscreve apenas os endereços novos, sem reprocessar
//     os já conhecidos
//   - Descritor removido → purga addrMap, shMap e state imediatamente;
//     o servidor Electrum ainda envia eventos mas são ignorados pois o
//     scriptHash não existe mais no shMap

// ─── REBALANCE GAP ────────────────────────────────────────────────────────────
// Chamado quando gapLimit muda no config.json.
//
// REDUÇÃO: remove do addrMap/shMap/state os endereços vazios (sem saldo e sem
//   txs) que ficaram além do novo gap — respeitando o gap a partir do último
//   endereço com histórico.
//
// AUMENTO: deriva e subscreve imediatamente os novos endereços em todas as
//   carteiras.

// Fila serializada — impede execuções concorrentes quando o gapLimit é alterado
// várias vezes em rápida sucessão. O segundo rebalance só começa após o primeiro
// terminar, garantindo que o state esteja consistente para calcular o cutoff.
let _rebalanceQueue = Promise.resolve();
function queueRebalance(prevGap, newGap, electrum) {
  _rebalanceQueue = _rebalanceQueue
    .then(() => rebalanceGap(prevGap, newGap, electrum))
    .catch(e => log.error('[gap] rebalanceGap:', e.message));
}

async function rebalanceGap(prevGap, newGap, electrum) {
  if (!electrum?.connected) return;
  log.info(`[gap] gapLimit alterado: ${prevGap} → ${newGap}`);

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

      // Índice do último endereço COM histórico (saldo > 0 ou txs > 0)
      let lastUsed = -1;
      for (const a of addrs) {
        const st = getAddrState(a.address, wallet.name);
        if ((st.balanceSat || 0) > 0 || (st.txids?.length || 0) > 0 || (st.mempoolTxids?.length || 0) > 0) {
          lastUsed = a.index;
        }
      }

      // ── REDUÇÃO: purga vazios além do novo gap ──────────────────────────
      if (newGap < prevGap) {
        const startIdx = wallet.startIndex ?? 0;
        // cutoff = último índice permitido:
        //   - Se há endereços com histórico: lastUsed + newGap
        //   - Se carteira totalmente vazia: startIdx + newGap - 1
        const base   = lastUsed >= 0 ? lastUsed : startIdx - 1;
        const cutoff = base + newGap;
        let purged = 0;

        for (const a of [...addrs]) {
          if (a.index <= cutoff) continue;
          const st = getAddrState(a.address, wallet.name);
          const hasHistory = (st.balanceSat || 0) > 0
            || (st.txids?.length || 0) > 0
            || (st.mempoolTxids?.length || 0) > 0;
          if (hasHistory) continue; // nunca remove endereço com histórico

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
          // Remove do state em memória — sem isso o saveState regrava o endereço
          const lbl = chain === 0 ? 'externo' : 'change';
          if (state[wallet.name]?.[lbl]) {
            delete state[wallet.name][lbl][a.address];
          }
          purged++;
        }

        const remaining = wallet.addresses.filter(a => a.chain === chain).length;
        if (purged > 0) {
          log.info(`  [gap] ${wallet.name} [${label}]: ${purged} endereços removidos (cutoff idx ${cutoff}, restam ${remaining})`);
          updateLockMsg(`reduzindo gap limit… "${wallet.name}" — ${purged} endereços removidos`);
          saveState();
        } else {
          log.info(`  [gap] ${wallet.name} [${label}]: nenhum endereço removido (cutoff idx ${cutoff}, total ${remaining})`);
        }
      }

      // ── AUMENTO: varredura sequencial a partir do último endereço com tx ──
      if (newGap > prevGap) {
        const desc             = (chain === 1 && wallet.descriptorChange) ? wallet.descriptorChange : wallet.descriptor;
        const lastIdx          = addrs.length ? Math.max(...addrs.map(a => a.index)) : -1;
        const startIdx         = wallet.startIndex ?? 0;
        let consecutiveEmpty   = 0;
        let i                  = Math.max(lastUsed + 1, startIdx);
        let added              = 0;
        let lastUsedInScan     = lastUsed;

        // Estimativa de endereços novos a indexar neste chain
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
          updateLockMsg(`aumentando gap limit… "${wallet.name}" [${label === 'ext' ? 'externo' : 'change'}] ${_done}/${Math.max(_done, _needed)} endereços`);

          await sleep(getCFG().subscribeDelayMs);
          added++;
          i++;
        }

        if (added > 0)
          log.info(`  [gap] ${wallet.name} [${label}]: +${added} endereços varridos, último com tx idx ${lastUsedInScan}`);
      }
    }
  }

  // Libera o lock de UI após conclusão
  writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
  log.info('[gap] rebalanceGap concluído — runtime lock liberado');
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
    // Ignora se já há uma troca de servidor pendente — evita múltiplas reconexões
    // disparadas pelo polling de 3s enquanto o loop ainda está reiniciando.
    if (_serverChangePending) return;
    _serverChangePending = true;
    log.info(`[hot-reload] Servidor Electrum alterado → ${ne.host}:${ne.port} — reconectando...`);
    _reconnectRequested = true;
    // Cancela o sleep de reconexão imediatamente
    if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
    // Destrói o socket imediatamente — o catch do loop vai ignorar o erro
    // pois _reconnectRequested já está true.
    if (_activeElectrum) {
      try { if (_activeElectrum.socket) _activeElectrum.socket.destroy(); } catch {}
      try { _activeElectrum.disconnect(); } catch {}
    }
    return;
  }

  // Detecta e loga todas as mudanças relevantes
  const changes = [];

  // Compara seções flat com label amigável
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
    log.info(`[hot-reload] config.json atualizado:\n  ${changes.join('\n  ')}`);
  else
    log.info('[hot-reload] config.json atualizado — sem mudanças relevantes detectadas');

  // Verifica mudança de gapLimit
  const prevGap = (prev.monitor || {}).gapLimit || 10;
  const nextGap = (next.monitor || {}).gapLimit || 10;
  if (prevGap !== nextGap && _activeElectrum?.connected) {
    queueRebalance(prevGap, nextGap, _activeElectrum);
  }
}

async function hotReloadWallets(electrum) {
  if (!electrum?.connected) return;
  const walletsFile = path.join(dataDir, 'wallets.json');
  let newList = [];
  try { newList = JSON.parse(fs.readFileSync(walletsFile, 'utf8')); } catch { return; }

  const newDescriptors  = new Set(newList.map(w => w.descriptor).filter(Boolean));
  const knownDescriptors = new Set(wallets.map(w => w.descriptor));

  // ── Descritores REMOVIDOS → limpa addrMap, shMap e state ─────────────────
  const removed = wallets.filter(w => w.descriptor && !newDescriptors.has(w.descriptor));
  if (removed.length) {
    for (const wallet of removed) {
      let count = 0;
      // Remove todos os endereços desse wallet do addrMap e shMap
      for (const [key, info] of addrMap.entries()) {
        if (info.wallet.name !== wallet.name) continue;
        addrMap.delete(key);
        // Remove entrada do shMap para este wallet
        const shList = shMap.get(info.scriptHash);
        if (shList) {
          const filtered = shList.filter(e => e.wallet.name !== wallet.name);
          if (filtered.length) shMap.set(info.scriptHash, filtered);
          else shMap.delete(info.scriptHash);
        }
        count++;
      }
      // Remove do state
      delete state[wallet.name];
      saveState();

      // Remove do txHistory — evita que transações da carteira removida
      // apareçam no histórico após remoção ou contaminem re-adições futuras.
      try {
        const th = readTxHistory();
        if (th[wallet.name]) {
          delete th[wallet.name];
          writeTxHistory(th);
          log.info(`[hot-reload] "${wallet.name}" — txHistory limpo`);
        }
      } catch(e) { log.warn(`[hot-reload] limpeza txHistory "${wallet.name}": ${e.message}`); }

      log.info(`[hot-reload] "${wallet.name}" removido — ${count} endereços purgados da memória`);
    }
    // Atualiza lista em memória
    wallets.splice(0, wallets.length, ...wallets.filter(w => newDescriptors.has(w.descriptor)));
  }

  // ── Descritores NOVOS → subscreve ────────────────────────────────────────
  const added = newList.filter(w => w.descriptor && !knownDescriptors.has(w.descriptor));

  if (!added.length && !removed.length) {
    log.info('[hot-reload] wallets.json atualizado — nenhuma mudança de descritores');
    return;
  }
  if (!added.length) {
    // Só remoções — libera lock imediatamente
    writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
    log.info('[hot-reload] remoção concluída — runtime lock liberado');
    return;
  }

  log.info(`[hot-reload] ${added.length} novo(s) descritor(es) detectado(s) — subscrevendo...`);

  // Para carteiras recém-adicionadas, garante que não há txHistory residual
  // de uma carteira com mesmo nome que foi removida anteriormente.
  for (const wallet of added) {
    try {
      const th = readTxHistory();
      if (th[wallet.name]) {
        delete th[wallet.name];
        writeTxHistory(th);
        log.info(`[hot-reload] txHistory residual de "${wallet.name}" limpo antes de re-indexar`);
      }
    } catch(e) { log.warn(`[hot-reload] limpeza txHistory pré-add "${wallet.name}": ${e.message}`); }
  }

  // Calcula total estimado de endereços a indexar (para progresso)
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
        updateLockMsg(`indexando "${wallet.name}" [${label}]… ${_totalDone}/${_totalNeeded} endereços`);

        await sleep(getCFG().subscribeDelayMs);
        i++;
        if (isSingle) break;
      }

      const total = wallet.addresses.filter(a => a.chain === chain).length;
      log.info(`  [hot-reload] ${wallet.name} [${label}]: ${total} endereços subscritos, último usado idx ${lastUsed}`);
    }
  }

  // Libera o lock de UI após todos os descritores adicionados serem indexados
  writeRuntime({ lock: { active: false, msg: '', since: null, timeoutAt: null } });
  log.info('[hot-reload] wallets indexadas — runtime lock liberado');
}

// Watcher com debounce de 1.5s
let _cfgRaw     = '';
let _walletsRaw = '';
let _hotTimer   = null;

try { _cfgRaw     = fs.readFileSync(path.join(dataDir, 'config.json'),  'utf8').trim(); } catch {}
try { _walletsRaw = fs.readFileSync(path.join(dataDir, 'wallets.json'), 'utf8').trim(); } catch {}

// ─── HOT-RELOAD via poll de conteúdo ─────────────────────────────────────────
// Lê e compara o conteúdo dos arquivos a cada 3s.
// Funciona em qualquer ambiente Docker/volume, independente de inotify.
const POLL_INTERVAL = 3000;

setInterval(() => {
  // ── config.json ──────────────────────────────────────────────────────────
  try {
    const raw = fs.readFileSync(path.join(dataDir, 'config.json'), 'utf8').trim();
    if (raw !== _cfgRaw) {
      // Valida JSON — arquivo pode estar sendo escrito
      try { JSON.parse(raw); } catch { /* JSON inválido — aguarda próximo ciclo */ return; }
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

log.info(`Hot-reload ativo — polling a cada ${POLL_INTERVAL/1000}s (config.json, wallets.json)`);