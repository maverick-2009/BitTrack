# ₿ BitTrack

> A self-hosted Bitcoin wallet monitoring daemon — real-time Telegram alerts for mempool and confirmed transactions, BTC price tracking, and new block notifications.

![Node.js](https://img.shields.io/badge/Node.js-20-green?logo=node.js)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![Bitcoin](https://img.shields.io/badge/Bitcoin-Mainnet-orange?logo=bitcoin)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [File Structure](#file-structure)
- [Installation (Docker)](#installation-docker)
- [Configuration](#configuration)
- [Module Reference](#module-reference)
  - [BitTrack.js](#bittrackjs)
  - [monitor.js](#monitorjs)
  - [descriptor-parser.js](#descriptor-parserjs)
  - [panel.js](#paneljs)
  - [panel.html](#panelhtml)
- [Data Files](#data-files)
- [Security Notes](#security-notes)

---

## Overview

**BitTrack** is a self-hosted Node.js daemon designed to run on your own infrastructure (e.g., an Umbrel node). It monitors Bitcoin wallets defined by output descriptors by connecting to a local Fulcrum or ElectrumX server via TCP/TLS. When a transaction involving a tracked address appears in the mempool or gets confirmed, BitTrack sends a Telegram notification instantly.

A lightweight web panel (`panel.html`) is served on port `8585` for configuration, wallet management, and status monitoring — no external dependencies or databases required.

---

## Features

- 🔍 **Wallet monitoring** via Bitcoin output descriptors (xpub, ypub, zpub, Ypub, Zpub, Taproot, Miniscript, `addr()`)
- ⚡ **Mempool alerts** — notified the moment a transaction enters the mempool
- ✅ **Confirmation alerts** — notified when a transaction is confirmed on-chain
- 📦 **New block notifications** (optional, configurable interval)
- 💵 **BTC price tracking** with configurable alert threshold (supports CoinGecko, Binance, Blockchain.info)
- 🔑 **Descriptor parsing** with zero external npm dependencies — pure Node.js implementation of BIP32, BIP380/BIP389, secp256k1, Base58Check, Bech32/Bech32m
- 🌐 **Web panel** for full configuration, wallet management, and live status
- 🔄 **Hot-reload** — changes to `config.json` and `wallets.json` are applied without restarting the process
- 🐳 **Docker-ready** — single `docker compose up -d --build` to run
- 📈 **Automatic gap limit scanning** for both external (chain 0) and change (chain 1) addresses
- 🔌 **TCP/TLS** connection to Fulcrum/ElectrumX with automatic reconnection

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    BitTrack.js                        │
│         (unified entry point — runs both below)       │
│                                                      │
│  ┌─────────────────────┐  ┌────────────────────────┐ │
│  │      panel.js        │  │      monitor.js         │ │
│  │  HTTP server :8585   │  │  Electrum subscriber   │ │
│  │  Config / Wallets    │  │  Gap-limit derivation  │ │
│  │  Auth / REST API     │  │  Tx classification     │ │
│  └──────────┬──────────┘  └──────────┬─────────────┘ │
│             │                        │                │
│             └──────────┬─────────────┘                │
│                        │                              │
│              ┌─────────▼──────────┐                   │
│              │  descriptor-       │                   │
│              │  parser.js         │                   │
│              │  (BIP32/380/389,   │                   │
│              │   secp256k1,       │                   │
│              │   Miniscript)      │                   │
│              └────────────────────┘                   │
└──────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
  Telegram Bot API          Fulcrum / ElectrumX
  (notifications)           blockchain.scripthash
                            .subscribe (TCP/TLS)
```

Both `panel.js` and `monitor.js` run in the **same Node.js process**, with prefixed console output (`[PANEL]` / `[MONITOR]`) for easy log reading.

---

## File Structure

```
BitTrack/
├── BitTrack.js             # Entry point — starts panel.js and monitor.js together
├── monitor.js              # Core daemon — Electrum connection, subscriptions, Telegram alerts
├── descriptor-parser.js    # Output descriptor parser and address derivation engine
├── panel.js                # HTTP server for the web panel (no Express dependency)
├── panel.html              # Web UI dashboard
├── Dockerfile              # Docker image (node:20-alpine)
├── docker-compose.yml      # Docker Compose deployment
├── descriptors-test.txt    # Sample descriptors for CLI testing
└── data/
    ├── config.json         # Main configuration (Electrum, Telegram, notifications)
    ├── wallets.json        # List of monitored wallets and their descriptors
    ├── state.json          # Persisted address states (balances, txids, status hashes)
    ├── servers.json        # Saved Electrum server list for the panel UI
    ├── panel-auth.json     # Panel password hash (SHA-256 + salt)
    └── runtime.json        # Volatile runtime data (price, Electrum status, UI lock)
```

---

## Installation (Docker)

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2+
- A running **Fulcrum** or **ElectrumX** instance reachable from the container
- A **Telegram Bot Token** (from [@BotFather](https://t.me/BotFather))
- Your Telegram **Chat ID**

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/maverick-2009/BitTrack.git
cd BitTrack
```

---

### Step 2 — Build and start

The `data/` directory ships with example config files that are copied into the container by the Dockerfile. You can edit them before building, or configure everything through the web panel after startup.

```bash
docker compose up -d --build
```

Check logs:

```bash
docker compose logs -f bittrack
```

---

### Step 3 — Open the web panel

```
http://<your-server-ip>:8585
```

Default password: **`admin`**

> Change it immediately in **Settings → Panel Password**.

---

### Step 4 — Configure Electrum and Telegram

In the panel go to **Settings** and fill in:

- **Electrum server** — host, port, and TLS toggle. Use **Test Connection** to verify.
- **Telegram** — bot token and chat ID. Use **Send Test Message** to verify.

The monitor will automatically (re)connect once valid credentials are saved — no restart needed.

---

### Step 5 — Add your first wallet

In the panel go to **Wallets → Add Wallet**. Paste your output descriptor. Examples:

```
wpkh([xxxxxxxx/84'/0'/0']xpub.../<0;1>/*)
wsh(multi(2,[fp1/48'/0'/0'/2']Zpub.../<0;1>/*,[fp2/48'/0'/0'/2']Zpub.../<0;1>/*))
addr(bc1q...)
```

The panel normalizes the descriptor, previews the derived addresses, and saves to `wallets.json`. The monitor picks up the change via hot-reload and starts subscribing within 3 seconds.

---

### Updating

```bash
git pull
docker compose up -d --build
```

### Stopping

```bash
docker compose down
```

---

## Configuration

All configuration lives in `data/config.json`. The monitor reads it from disk on every operation — changes made in the panel take effect without a restart.

### `electrum`

| Field | Default | Description |
|---|---|---|
| `host` | `""` | IP or hostname of your Fulcrum/ElectrumX server |
| `port` | `50002` | TCP port (50001 = plain, 50002 = TLS) |
| `tls` | `false` | Enable TLS (self-signed certs accepted) |
| `name` | `"Local"` | Display name in the panel |

### `telegram`

| Field | Default | Description |
|---|---|---|
| `token` | `""` | Bot token from @BotFather |
| `chatId` | `""` | Target chat ID for notifications |

### `general`

| Field | Default | Description |
|---|---|---|
| `panelPort` | `8585` | HTTP port for the web panel |
| `mempoolExplorer` | `"https://mempool.space/"` | Base URL for transaction links in alerts |
| `currency` | `"USD"` | Display currency for price info |
| `timezone` | `"America/Sao_Paulo"` | Timezone for timestamps in logs and alerts |
| `dateLocale` | `"pt-BR"` | Locale for date formatting |

### `monitor`

| Field | Default | Description |
|---|---|---|
| `gapLimit` | `10` | Consecutive empty addresses before stopping derivation |
| `maxIndex` | `1000` | Hard cap on address index to prevent runaway derivation |
| `pingIntervalSec` | `60` | Keepalive ping interval to the Electrum server |
| `subscribeDelayMs` | `0` | Delay between consecutive subscribe calls (rate limiting) |
| `priceApis` | `["coingecko","binance","blockchain.info"]` | Price source priority list |
| `priceCheckIntervalSec` | `300` | How often to fetch the BTC price |
| `priceRefMaxDeviationPct` | `20` | Max allowed deviation (%) from reference price before resetting it |
| `priceThresholdMinPct` | `1` | Minimum alert threshold in % |
| `priceThresholdMaxPct` | `50` | Maximum alert threshold in % |

### `notifications`

| Field | Default | Description |
|---|---|---|
| `mempoolPending` | `true` | Alert when a tx enters the mempool |
| `txConfirmed` | `true` | Alert when a tx is confirmed |
| `everyBlock` | `false` | Alert for every new block |
| `blockIntervalMin` | `0` | Alert only every N minutes (0 = every block) |
| `priceChange` | `false` | Enable price change alerts |
| `priceThresholdPct` | `1` | Price must move this % from reference to trigger an alert |
| `priceReference` | `null` | Reference price; `null` = use current price on startup |

---

## Module Reference

### `BitTrack.js`

Unified entry point. Loads `panel.js` and `monitor.js` in the same process and patches `console.log/warn/error` so that every log line is prefixed with `[PANEL]` or `[MONITOR]`, preserving all timestamps and emoji from the original modules.

```bash
node BitTrack.js
```

---

### `monitor.js`

Core monitoring daemon. Connects to Fulcrum/ElectrumX over TCP or TLS and manages all subscriptions. No npm dependencies — uses Node.js built-in `net`, `tls`, `https`, `crypto`, and `fs`.

| Feature | Description |
|---|---|
| `ensureConfig()` | Reads `config.json` on boot, fills missing fields with defaults, writes the merged result back |
| `loadConfig()` / `getCFG()` | Reads `config.json` from disk on every call — no in-memory cache, so panel changes are always reflected |
| Electrum connection | Persistent TCP/TLS connection using JSON-RPC newline-delimited protocol; auto-reconnects after 10 s on disconnect |
| `blockchain.scripthash.subscribe` | Subscribes every derived address; Electrum pushes a status hash whenever the address history changes |
| Gap limit scanning | Iterates external (chain 0) and change (chain 1) addresses per wallet, stopping after `gapLimit` consecutive unused addresses |
| Transaction classification | On a status change, fetches full tx history and raw hex, then classifies each new tx as **incoming**, **outgoing**, **outgoing + change**, or **consolidation** |
| Anti-duplicate | Every TXID is stored in `state.json`; the same transaction is never notified twice across restarts |
| Price monitoring | Polls CoinGecko, Binance, and Blockchain.info; uses a median with deviation guard; writes the result to `runtime.json` |
| Block notifications | Subscribes to `blockchain.headers.subscribe`; fires a Telegram alert per block or per configurable minute interval |
| Hot-reload (config) | Polls `config.json` every 3 s; on change, logs the diff and reconnects to Electrum only if server settings changed |
| Hot-reload (wallets) | Polls `wallets.json` every 3 s; adds new wallets by subscribing their addresses and removes purged wallets from memory and `state.json` |
| `runtime.json` | Writes real-time data (price, Electrum status, UI lock) for the panel to consume without a direct process link |
| `saveState()` | Persists the full address state map to `state.json` after every relevant change |

---

### `descriptor-parser.js`

Pure Node.js implementation of Bitcoin descriptor parsing and address derivation — zero npm dependencies. Implements secp256k1 point arithmetic, BIP32 public key derivation, Base58Check, Bech32, and Bech32m entirely from scratch.

**Supported descriptor types:**

| Descriptor | Address type |
|---|---|
| `pk(...)` | P2PK |
| `pkh(...)` | P2PKH (Legacy, `1…`) |
| `wpkh(...)` | P2WPKH (Native SegWit, `bc1q…`) |
| `sh(wpkh(...))` | P2SH-P2WPKH (Wrapped SegWit, `3…`) |
| `wsh(multi(...))` | P2WSH Multisig |
| `wsh(sortedmulti(...))` | P2WSH Sorted Multisig |
| `wsh(<miniscript>)` | P2WSH Miniscript (`thresh`, `and_v`, `or_b`, `older`, `after`, `sha256`, …) |
| `addr(<address>)` | Single static address (P2PKH, P2SH, P2WPKH, P2TR) |

**Supported key prefixes:** `xpub`, `ypub`, `zpub`, `Ypub`, `Zpub`, `tpub`, `upub`, `vpub`, `Upub`, `Vpub` — all normalized to `xpub` bytes internally for uniform derivation.

**Key exports:**

| Export | Description |
|---|---|
| `analyzeDescriptor(descriptor, { deriveSpec })` | Main entry point. Parses the descriptor and derives addresses for the given `deriveSpec` (`[{ index, chain }]`). Returns `{ scriptType, miniscript, keys, addresses, errors }` |
| `parseNode(descriptor)` | Parses a descriptor string into an AST node (recursive) |
| `parseKeyExpression(str)` | Parses a single key expression including fingerprint, origin path, and derivation path |
| `ExtendedKey` | BIP32 extended public key class with `fromBase58()` and `derive(index)` |
| `derivePublicKey(keyExpr, index, chain)` | Derives a compressed public key at a given index and chain from a key expression |
| `compileScript(node, index, chain)` | Compiles a parsed AST node into a Bitcoin script buffer |
| `scriptToAddress(compiled, hrp)` | Converts a compiled script to a Bitcoin address string |
| `scriptToScriptHash(scriptHex)` | Converts a script hex string to the reversed SHA-256 scripthash required by Electrum |
| `compileRedeemScript(node, index, chain)` | Compiles the inner redeem/witness script for P2SH and P2WSH descriptors |

**CLI usage:**

```bash
# Derive index 0 (default)
node descriptor-parser.js "wpkh([xxxxxxxx/84'/0'/0']xpub.../<0;1>/*)"

# Derive a range of indices
node descriptor-parser.js "wsh(multi(2,...))" --range 0 9

# Derive specific indices on the change chain
node descriptor-parser.js "wsh(...)" --index 0 1 5 --change
```

---

### `panel.js`

Lightweight HTTP server built with Node.js built-ins only (`http`, `https`, `net`, `tls`, `fs`, `crypto`) — no Express or other npm frameworks.

**Authentication:** Session-token based. On login, the submitted password is hashed with SHA-256 + a static salt and compared against `panel-auth.json`. A 64-byte hex token is issued and must be sent as the `X-Auth-Token` header on all subsequent API requests. Default password: `admin`.

**REST API:**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/login` | Authenticate; returns a session token |
| `POST` | `/api/logout` | Invalidate the current session token |
| `POST` | `/api/change-password` | Update the panel password |
| `GET` | `/api/config` | Read `config.json` |
| `POST` | `/api/config` | Write `config.json`; monitor picks up changes via hot-reload |
| `GET` | `/api/wallets` | Read `wallets.json` |
| `POST` | `/api/wallets` | Write `wallets.json`; sets a runtime lock while the monitor indexes new wallets |
| `GET` | `/api/servers` | Read the saved Electrum server list |
| `POST` | `/api/servers` | Save the Electrum server list |
| `GET` | `/api/state` | Read `state.json` (per-address balances and txids) |
| `GET` | `/api/price` | Read the current BTC price from `runtime.json` |
| `GET` | `/api/server-status` | Read Electrum connection status from `runtime.json` |
| `POST` | `/api/test-server` | Open a live TCP/TLS connection to test an Electrum server (`server.version` handshake) |
| `POST` | `/api/test-telegram` | Send a test Telegram message to verify bot credentials |
| `POST` | `/api/derive` | Normalize a descriptor and return derived addresses for preview |
| `POST` | `/api/wallet-ready` | Poll whether the monitor has finished indexing a newly added wallet |
| `POST` | `/api/gap-ready` | Poll whether a gap limit change has been fully applied to all wallets |
| `GET/POST` | `/api/runtime-lock` | Read or set the UI overlay lock (used during long indexing operations) |
| `GET` | `/` | Serve `panel.html` |

---

### `panel.html`

Single-file web UI. Communicates with `panel.js` exclusively via the REST API above. All styling and JavaScript are self-contained — no external CDN dependencies.

---

## Data Files

| File | Description |
|---|---|
| `data/config.json` | All settings: Electrum, Telegram, general, monitor, notifications |
| `data/wallets.json` | Array of wallet objects: `{ name, descriptor, descriptorChange?, addresses[], startIndex? }` |
| `data/state.json` | Per-wallet, per-address state: `{ balanceSat, txids[], mempoolTxids[], statusHash }` |
| `data/servers.json` | Saved Electrum servers shown in the panel dropdown |
| `data/panel-auth.json` | SHA-256 password hash for panel login |
| `data/runtime.json` | Volatile data written by the monitor: price, Electrum status, UI lock |

> **Backup tip:** copying the entire `data/` directory is sufficient to fully restore BitTrack, including all wallet state and configuration.

The `data/` directory is stored in a named Docker volume (`data`) defined in `docker-compose.yml` and persists across container rebuilds and updates.

---

## Security Notes

- The web panel has **no HTTPS** by default. Place it behind a reverse proxy (IIS, Nginx, Caddy) with TLS before exposing it outside your local network.
- The default panel password is `admin` — change it on first login.
- `wallets.json` is stored **in plain text** on disk. Secure access to the `data/` Docker volume at the OS level.
- BitTrack is **read-only** with respect to the Bitcoin network — it only subscribes to and reads data from Electrum, it never constructs or broadcasts transactions.
- The Electrum connection accepts self-signed TLS certificates (`rejectUnauthorized: false`), which is appropriate for a local node but should be considered if pointing to a remote server.

---

## License

MIT © [maverick-2009](https://github.com/maverick-2009)
