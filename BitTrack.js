/**
 * BitTrack — unified entry point
 * Runs the web panel (panel.js) and the monitor (monitor.js) in the same process.
 *
 * Usage: node BitTrack.js
 */

'use strict';

const path = require('path');

// ─── UNIFIED LOGGING ──────────────────────────────────────────────────────────
// Prefixes each line with a tag identifying the source: [PANEL] or [MONITOR]
// Preserves colors and emojis from the original loggers.

function patchConsole(tag) {
  const PAD   = 9; // fixed tag width to align columns
  const label = `[${tag}]`.padEnd(PAD);

  const wrap = (original) => (...args) => {
    // If the first argument already contains the monitor timestamp ([YYYY-MM-DD...])
    // insert the tag right after the timestamp to preserve the format.
    if (typeof args[0] === 'string' && args[0].startsWith('[')) {
      const first = args[0];
      const rest  = args.slice(1);
      // e.g. "[2026-03-19 15:00:00] ℹ️  " → "[2026-03-19 15:00:00] [MONITOR] ℹ️  "
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

// Save originals before any patching
console._log   = console.log.bind(console);
console._warn  = console.warn.bind(console);
console._error = console.error.bind(console);

// ─── START PANEL ──────────────────────────────────────────────────────────────
;(() => {
  const p = patchConsole('PANEL');
  // Temporarily override console while panel.js is loaded
  console.log   = p.log;
  console.warn  = p.warn;
  console.error = p.error;

  require('./panel.js');
})();

// ─── START MONITOR ────────────────────────────────────────────────────────────
;(() => {
  const m = patchConsole('MONITOR');
  console.log   = m.log;
  console.warn  = m.warn;
  console.error = m.error;

  require('./monitor.js');
})();