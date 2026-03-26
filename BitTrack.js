/**
 * BitTrack — ponto de entrada unificado
 * Executa o painel web (panel.js) e o monitor (monitor.js) no mesmo processo.
 *
 * Uso: node BitTrack.js
 */

'use strict';

const path = require('path');

// ─── LOGS UNIFICADOS ──────────────────────────────────────────────────────────
// Prefixa cada linha com uma tag identificando a origem: [PANEL] ou [MONITOR]
// Mantém cores e emojis dos logs originais.

function patchConsole(tag) {
  const PAD   = 9; // largura fixa da tag para alinhar colunas
  const label = `[${tag}]`.padEnd(PAD);

  const wrap = (original) => (...args) => {
    // Se o primeiro argumento já contém o timestamp do monitor ([YYYY-MM-DD...])
    // insere a tag logo após o timestamp para não quebrar o formato.
    if (typeof args[0] === 'string' && args[0].startsWith('[')) {
      const first = args[0];
      const rest  = args.slice(1);
      // Ex: "[2026-03-19 15:00:00] ℹ️  " → "[2026-03-19 15:00:00] [MONITOR] ℹ️  "
      const patched = first.replace(/^(\[\d{2}[\-\/]\d{2}[\-\/]\d{4}[,\s]+\d{2}:\d{2}:\d{2}\])\s*/, `$1 ${label} `);
      original(patched, ...rest);
    } else {
      original(`${label}`, ...args);
    }
  };

  return {
    log:   wrap(console._log   || console.log),
    warn:  wrap(console._warn  || console.warn),
    error: wrap(console._error || console.error),
  };
}

// Salva os originais antes de qualquer patch
console._log   = console.log.bind(console);
console._warn  = console.warn.bind(console);
console._error = console.error.bind(console);

// ─── INICIA PAINEL ────────────────────────────────────────────────────────────
;(() => {
  const p = patchConsole('PANEL');
  // Sobrescreve console temporariamente enquanto panel.js é carregado
  console.log   = p.log;
  console.warn  = p.warn;
  console.error = p.error;

  require('./panel.js');
})();

// ─── INICIA MONITOR ───────────────────────────────────────────────────────────
;(() => {
  const m = patchConsole('MONITOR');
  console.log   = m.log;
  console.warn  = m.warn;
  console.error = m.error;

  require('./monitor.js');
})();