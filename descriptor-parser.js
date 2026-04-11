// @ts-nocheck
/**
 * descriptor-parser.js
 * Full Output Descriptor parser for Bitcoin (BIP380/BIP389)
 *
 * Supports:
 *   • Keys with fingerprint+path: [xxxxxxxxx/48'/0'/0'/2']xpub...
 *   • Descriptors: pk, pkh, wpkh, sh(wpkh), wsh(multi), wsh(thresh...)
 *   • Full Miniscript inside wsh(...)
 *   • Address derivation: xpub.../0/*, xpub.../1/* (change)
 */

'use strict';

const crypto = require('crypto');

// ─── BASE58CHECK ──────────────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b58Decode(str) {
  let n = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`Invalid base58 char: '${c}'`);
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const buf = Buffer.from(hex, 'hex');
  const leading = str.match(/^1*/)[0].length;
  return Buffer.concat([Buffer.alloc(leading), buf]);
}

function b58CheckDecode(str) {
  const buf = b58Decode(str);
  const payload  = buf.slice(0, -4);
  const checksum = buf.slice(-4);
  const hash = sha256d(payload).slice(0, 4);
  if (!hash.equals(checksum)) throw new Error('Invalid base58check checksum');
  return payload;
}

function sha256(buf)  { return crypto.createHash('sha256').update(buf).digest(); }
function sha256d(buf) { return sha256(sha256(buf)); }
function ripemd160(buf) { return crypto.createHash('ripemd160').update(buf).digest(); }
function hash160(buf)   { return ripemd160(sha256(buf)); }

// ─── BECH32 ───────────────────────────────────────────────────────────────────
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_GEN     = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
  ret.push(0);
  for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
  return ret;
}

function convertBits(data, from, to, pad = true) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}

function decodeBech32(addr) {
  const lower = addr.toLowerCase();
  const pos = lower.lastIndexOf('1');

  const hrp = lower.slice(0, pos);
  const data = lower.slice(pos + 1);

  const values = data.split('').map(c => BECH32_CHARSET.indexOf(c));

  const version = values[0];
  const program = convertBits(values.slice(1, -6), 5, 8, false);

  return {
    hrp,
    version,
    program
  };
}

function bech32Encode(hrp, data, bech32m = false) {
  const combined = [...bech32HrpExpand(hrp), ...data];
  const mod = bech32Polymod([...combined, 0, 0, 0, 0, 0, 0]) ^ (bech32m ? 0x2bc830a3 : 1);
  const checksum = Array.from({ length: 6 }, (_, i) => (mod >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map(d => BECH32_CHARSET[d]).join('');
}

function witnessToAddress(program, version, hrp = 'bc') {
  const converted = convertBits(Array.from(program), 8, 5);
  const data = [version, ...converted];
  return bech32Encode(hrp, data, version > 0); // version>0 = bech32m
}

// ─── SECP256K1 (only operations needed for BIP32) ──────────────────────────────
// Minimal implementation — point addition and scalar multiplication
const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function modP(n)    { return ((n % P) + P) % P; }
function modN(n)    { return ((n % N) + N) % N; }
function modInv(a, m) {
  let [old_r, r] = [a, m], [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - (q * s)];
  }
  return ((old_s % m) + m) % m;
}

// Modular exponentiation — avoids BigInt overflow from direct **
function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = result * base % mod;
    base = base * base % mod;
    exp >>= 1n;
  }
  return result;
}

function pointAdd(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  if (x1 === x2) {
    if (y1 !== y2) return null; // point at infinity
    // lam = 3*x1^2 / (2*y1)  mod P
    const n1  = (((3n * x1) % P) * x1) % P;
    const d1  = (2n * y1) % P;
    const lam = (n1 * modInv(d1, P)) % P;
    const x3  = (lam * lam % P - 2n * x1 + 2n * P) % P;
    return [x3, (lam * ((x1 - x3 + P) % P) % P - y1 + P) % P];
  }
  // lam = (y2 - y1) / (x2 - x1)  mod P
  const num = (y2 - y1 + P) % P;
  const den = (x2 - x1 + P) % P;
  const lam = (num * modInv(den, P)) % P;
  const x3  = (lam * lam % P - x1 - x2 + 2n * P) % P;
  return [x3, (lam * ((x1 - x3 + P) % P) % P - y1 + P) % P];
}

function pointMul(k, point = [Gx, Gy]) {
  // Reduce k mod N before loop — avoids unnecessary iterations
  k = ((k % N) + N) % N;
  let result = null, addend = point;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

// Recover secp256k1 point from a compressed public key
function pubkeyToPoint(pubkeyBuf) {
  const prefix = pubkeyBuf[0];
  const x = BigInt('0x' + pubkeyBuf.slice(1).toString('hex'));
  const y2 = (modPow(x, 3n, P) + 7n) % P;
  let y = modPow(y2, (P + 1n) / 4n, P);
  // Check parity
  if ((y & 1n) !== BigInt(prefix & 1)) y = (P - y) % P;
  // Validate that the point is on the curve
  if ((y * y % P) !== y2) throw new Error('Invalid pubkey — point not on curve');
  return [x, y];
}

function compressPoint(point) {
  const [x, y] = point;
  const prefix = (y & 1n) ? 0x03 : 0x02;
  const xBuf = Buffer.from(x.toString(16).padStart(64, '0'), 'hex');
  return Buffer.concat([Buffer.from([prefix]), xBuf]);
}

// ─── BIP32 ────────────────────────────────────────────────────────────────────
const XPUB_VERSION  = Buffer.from([0x04, 0x88, 0xB2, 0x1E]);

// Version bytes for all variants — normalized to xpub before parsing
const KNOWN_XPUB_VERSIONS = {
  '0488b21e': 'xpub',  // mainnet P2PKH/P2SH
  '049d7cb2': 'ypub',  // mainnet P2SH-P2WPKH (BIP49)
  '04b24746': 'zpub',  // mainnet P2WPKH (BIP84)
  '0295b43f': 'Ypub',  // mainnet P2WSH-in-P2SH multisig
  '02aa7ed3': 'Zpub',  // mainnet P2WSH multisig
  '043587cf': 'tpub',  // testnet P2PKH
  '044a5262': 'upub',  // testnet P2SH-P2WPKH
  '045f1cf6': 'vpub',  // testnet P2WPKH
  '024289ef': 'Upub',  // testnet P2WSH-in-P2SH
  '02575483': 'Vpub',  // testnet P2WSH
};

class ExtendedKey {
  constructor({ depth, fingerprint, index, chainCode, key }) {
    this.depth       = depth;
    this.fingerprint = fingerprint;
    this.index       = index;
    this.chainCode   = chainCode;
    this.key         = key; // 33-byte Buffer (compressed pubkey)
  }

  static fromBase58(str) {
    const buf = b58CheckDecode(str);
    if (buf.length !== 78) throw new Error(`Invalid xpub length: ${buf.length}`);
    // Normalize ypub/zpub/Ypub/Zpub/tpub/upub/vpub → xpub (same key bytes, only version changes)
    const version = buf.slice(0, 4).toString('hex').toLowerCase();
    if (version !== '0488b21e') {
      if (!KNOWN_XPUB_VERSIONS[version]) throw new Error(`Unknown version bytes: ${version}`);
      buf.set(XPUB_VERSION, 0);
    }
    return new ExtendedKey({
      depth:       buf[4],
      fingerprint: buf.slice(5, 9),
      index:       buf.readUInt32BE(9),
      chainCode:   buf.slice(13, 45),
      key:         buf.slice(45, 78),
    });
  }

  // Normal public derivation (index < 0x80000000)
  derive(index) {
    if (index >= 0x80000000) throw new Error('Hardened derivation not supported on xpub');
    const data = Buffer.alloc(37);
    this.key.copy(data, 0);
    data.writeUInt32BE(index, 33);

    const I    = crypto.createHmac('sha512', this.chainCode).update(data).digest();
    const IL   = I.slice(0, 32);
    const IR   = I.slice(32);
    const ILn  = BigInt('0x' + IL.toString('hex'));
    if (ILn >= N) throw new Error('Invalid derivation — IL >= N');

    const parentPoint = this._pubkeyToPoint();
    const childPoint  = pointAdd(pointMul(ILn), parentPoint);
    if (!childPoint) throw new Error('Derivation resulted in point at infinity');

    const fp = hash160(this.key).slice(0, 4);
    return new ExtendedKey({
      depth:       this.depth + 1,
      fingerprint: fp,
      index,
      chainCode:   IR,
      key:         compressPoint(childPoint),
    });
  }

  // Derive by relative path: "0/0", "0/*" returns node
  deriveByPath(pathStr) {
    const parts = pathStr.replace(/^m\//, '').split('/').filter(Boolean);
    let node = this;
    for (const part of parts) {
      if (part === '*') return node; // return parent key for later derivation
      const hardened = part.endsWith("'") || part.endsWith('h');
      const idx = parseInt(hardened ? part.slice(0, -1) : part);
      node = node.derive(hardened ? (idx + 0x80000000) >>> 0 : idx);
    }
    return node;
  }

  pubkeyAt(index) {
    return this.derive(index).key;
  }

  _pubkeyToPoint() {
    return pubkeyToPoint(this.key);
  }
}

// ─── KEY EXPRESSION PARSER ───────────────────────────────────────────────────
// Parses: [fingerprint/path]xpub... or xpub... or <hex_pubkey>
function parseKeyExpression(expr) {
  expr = expr.trim();
  let origin = null, keyStr = expr;

  // Extract origin: [fingerprint/path]
  const originMatch = expr.match(/^\[([0-9a-fA-F]{8})(\/[^[\]]+)?\](.+)$/);
  if (originMatch) {
    origin = {
      fingerprint: originMatch[1],
      path:        originMatch[2] ? originMatch[2].slice(1) : '',
    };
    keyStr = originMatch[3];
  }

  // Extract derivation path after the key
  // Supports: /0/*, /1/*, /<0;1>/*, /* and combinations
  let derivPath = null;
  let multipath = null; // { ext: '0', chg: '1' } for /<0;1>/*

  const slashIdx = keyStr.indexOf('/');
  if (slashIdx > 0) {
    derivPath = keyStr.slice(slashIdx + 1);
    keyStr    = keyStr.slice(0, slashIdx);

    // Detect BIP389 multipath: /<a;b>/* or <a;b>/*
    const multipathMatch = derivPath.match(/^<(\d+);(\d+)>\/\*$/);
    if (multipathMatch) {
      multipath = { ext: multipathMatch[1], chg: multipathMatch[2] };
      derivPath = null; // will be resolved during chain derivation
    }
  }

  // Key type
  let type, xpub = null, rawPubkey = null;
  if (/^[0-9a-fA-F]{66}$/.test(keyStr)) {
    type      = 'raw_pubkey';
    rawPubkey = Buffer.from(keyStr, 'hex');
  } else if (/^[xyYzZtuUvVtT]pub/.test(keyStr)) {
    type = 'xpub';
    try { xpub = ExtendedKey.fromBase58(keyStr); }
    catch(e) { throw new Error(`Invalid xpub: ${e.message}`); }
  } else if (/^[xyYzZtuUvV]prv/.test(keyStr)) {
    throw new Error('Private keys (xprv) are not accepted — use xpub only');
  } else {
    type = 'named';
  }

  return { origin, type, keyStr, xpub, rawPubkey, derivPath, multipath };
}

// ─── PUBKEY DERIVATION ───────────────────────────────────────────────────────
// chain: 0 = external/receive, 1 = change
function derivePublicKey(keyExpr, index = 0, chain = 0) {
  if (keyExpr.type === 'raw_pubkey') return keyExpr.rawPubkey;
  if (keyExpr.type === 'named')      return null;

  const { xpub, derivPath, multipath } = keyExpr;
  if (!xpub) return null;

  // BIP389 /<a;b>/* — choose branch by chain
  if (multipath) {
    const branch = chain === 0 ? parseInt(multipath.ext) : parseInt(multipath.chg);
    return xpub.derive(branch).derive(index).key;
  }

  if (!derivPath) return xpub.key;

  // Normal format: "0/*", "1/*", "0/1/*", etc.
  const parts = derivPath.split('/');
  let node = xpub;
  for (const part of parts) {
    if (part === '*') {
      node = node.derive(index);
    } else if (part !== '') {
      node = node.derive(parseInt(part));
    }
  }
  return node.key;
}

// ─── DESCRIPTOR PARSER ──────────────────────────────────────────────────────
// Tokenize the expression respecting parentheses
function tokenizeDescriptor(str) {
  str = str.trim().replace(/\s+/g, '');
  // Strip checksum (#xxxx) if present
  const hashIdx = str.lastIndexOf('#');
  if (hashIdx > 0) str = str.slice(0, hashIdx);
  return str;
}

// Recursively parse a descriptor/miniscript node
function parseNode(str) {
  str = str.trim();

  // Identify function and arguments
  const parenIdx = str.indexOf('(');
  if (parenIdx < 0) {
    // Leaf key expression
    return { type: 'key', key: parseKeyExpression(str) };
  }

  const fn   = str.slice(0, parenIdx);
  const inner = str.slice(parenIdx + 1, str.length - 1);
  const args  = splitArgs(inner);

  // Wrappers (e.g. "v:pk(x)", "s:pk(x)")
  if (fn.includes(':')) {
    const [wrappers, realFn] = fn.split(':');
    const child = parseNode(`${realFn}(${inner})`);
    return { type: 'wrapped', wrappers: wrappers.split(''), child };
  }

  switch (fn) {
    case 'pk':
    case 'pk_k':
    case 'pk_h':
      return { type: fn, key: parseKeyExpression(args[0]) };

    case 'pkh':
      return { type: 'pkh', key: parseKeyExpression(args[0]) };

    case 'wpkh':
      return { type: 'wpkh', key: parseKeyExpression(args[0]) };

    case 'sh':
      return { type: 'sh', child: parseNode(args[0]) };

    case 'wsh':
      return { type: 'wsh', child: parseNode(args[0]) };

    case 'tr': {
      // Taproot: tr(internal_key) or tr(internal_key, script_tree)
      const internalKey = parseKeyExpression(args[0]);
      const scriptTree  = args[1] ? parseNode(args[1]) : null;
      return { type: 'tr', key: internalKey, scriptTree };
    }

    case 'combo':
      return { type: 'combo', key: parseKeyExpression(args[0]) };

    case 'multi':
    case 'sortedmulti': {
      const k    = parseInt(args[0]);
      const keys = args.slice(1).map(parseKeyExpression);
      return { type: fn, k, keys };
    }

    case 'thresh': {
      const k       = parseInt(args[0]);
      const children = args.slice(1).map(parseNode);
      return { type: 'thresh', k, children };
    }

    case 'older':
      return { type: 'older', value: parseInt(args[0]) };

    case 'after':
      return { type: 'after', value: parseInt(args[0]) };

    case 'sha256':
    case 'hash256':
    case 'ripemd160':
    case 'hash160':
      return { type: fn, hash: args[0] };

    case 'and_v': case 'and_b': case 'and_n':
      return { type: fn, left: parseNode(args[0]), right: parseNode(args[1]) };

    case 'or_b': case 'or_c': case 'or_d': case 'or_i':
      return { type: fn, left: parseNode(args[0]), right: parseNode(args[1]) };

    case 'andor':
      return { type: 'andor', x: parseNode(args[0]), y: parseNode(args[1]), z: parseNode(args[2]) };

    case 'addr':
      return { type: 'addr', address: args[0] };

    case 'raw':
      return { type: 'raw', script: args[0] };

    default:
      return { type: 'unknown', fn, args };
  }
}

// Split top-level arguments respecting nested parentheses
function splitArgs(str) {
  const args = [];
  let depth = 0, start = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === '(') depth++;
    else if (str[i] === ')') depth--;
    else if (str[i] === ',' && depth === 0) {
      args.push(str.slice(start, i));
      start = i + 1;
    }
  }
  args.push(str.slice(start));
  return args;
}

// ─── TAPROOT TWEAK (BIP341) ──────────────────────────────────────────────────
// Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
function taggedHash(tag, msg) {
  const tagHash = crypto.createHash('sha256').update(Buffer.from(tag)).digest();
  return crypto.createHash('sha256')
    .update(tagHash).update(tagHash).update(msg)
    .digest();
}

// liftX: recover point with even y from x coordinate (BIP340)
function liftX(xBuf) {
  const x  = BigInt('0x' + xBuf.toString('hex'));
  const y2 = (modPow(x, 3n, P) + 7n) % P;
  let y = modPow(y2, (P + 1n) / 4n, P);
  if ((y * y % P) !== y2) return null;
  // Ensure even y (BIP340 uses even y)
  if (y % 2n !== 0n) y = P - y;
  return [x, y];
}

// Compila script tree para obter merkle root (BIP341)
function compileTapLeaf(scriptNode, index, chain) {
  if (!scriptNode) return null;
  // Tapscript uses x-only keys and different rules — isTapscript=true
  const compiled = compileRedeemScript(scriptNode, index, chain, true);
  if (!compiled || !compiled.script.length) return null;
  // TapLeaf hash: H_tapleaf(version || compact_size(script) || script)
  const version = Buffer.from([0xc0]); // TAPSCRIPT
  const script  = compiled.script;
  const lenBuf  = script.length < 0xfd
    ? Buffer.from([script.length])
    : Buffer.concat([Buffer.from([0xfd]), Buffer.from([script.length & 0xff, script.length >> 8])]);
  return taggedHash('TapLeaf', Buffer.concat([version, lenBuf, script]));
}

// Apply Taproot tweak to the internal key (BIP341 key-path)
// Returns 32-byte Buffer (x-only tweaked pubkey)
function taprootTweak(pubkeyBuf, scriptTree = null, index = 0, chain = 0) {
  try {
    const xOnly = pubkeyBuf.slice(1); // 32 bytes, x coordinate

    let merkleRoot;
    if (scriptTree) {
      // Compute merkle root of the script tree
      const leafHash = compileTapLeaf(scriptTree, index, chain);
      // Single-leaf tree: merkle root = leaf hash
      // Multi-leaf tree: H_tapbranch(left, right) — simplified for 1 leaf
      merkleRoot = leafHash || Buffer.alloc(32);
    } else {
      // Key-path without script tree: tweak with empty merkle root
      merkleRoot = Buffer.alloc(0);
    }

    // t = H_taptweak(P || merkle_root)
    const tweak = taggedHash('TapTweak', Buffer.concat([xOnly, merkleRoot]));
    const t     = BigInt('0x' + tweak.toString('hex'));
    if (t >= N) return null;

    // Q = P + t*G  (BIP341)
    // liftX ensures P has even y; Q may have any y, but we only use x
    const P_point = liftX(xOnly);
    if (!P_point) return null;

    const tG      = pointMul(t);
    const tweaked = pointAdd(P_point, tG);
    if (!tweaked) return null;

    // Return only the x coordinate (32 bytes) — BIP340 x-only
    return Buffer.from(tweaked[0].toString(16).padStart(64, '0'), 'hex');
  } catch(e) {
    return null;
  }
}

// ─── SCRIPT COMPILATION ─────────────────────────────────────────────────────
// Generate the scriptPubKey from the parsed node + derivation index
function compileScript(node, index = 0, chain = 0) {
  switch (node.type) {
    case 'tr': {
      // P2TR key-path spend: OP_1 <32-byte-x-only-tweaked-pubkey>
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      // Taproot tweak: P + H(P||merkle_root)*G
      // Key-path without script tree: tweak = H_taptweak(P)
      const xOnly = pk.slice(1); // strip 02/03 prefix, keep only x (32 bytes)
      const tweakedX = taprootTweak(pk, node.scriptTree, index, chain);
      if (!tweakedX) return null;
      return {
        script:     Buffer.concat([Buffer.from([0x51, 0x20]), tweakedX]),
        type:       'P2TR',
        xOnlyPubkey: tweakedX.toString('hex'),
      };
    }

    case 'wpkh': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      const h  = hash160(pk);
      return { script: Buffer.concat([Buffer.from([0x00, 0x14]), h]), type: 'P2WPKH' };
    }

    case 'pkh': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      const h  = hash160(pk);
      return {
        script: Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h, Buffer.from([0x88, 0xac])]),
        type: 'P2PKH',
      };
    }

    case 'pk':
    case 'pk_k': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      return {
        script: Buffer.concat([Buffer.from([0x21]), pk, Buffer.from([0xac])]),
        type: 'P2PK',
      };
    }

    case 'sh': {
      const inner = compileRedeemScript(node.child, index, chain);
      if (!inner) return null;
      const h = hash160(inner.script);
      return {
        script: Buffer.concat([Buffer.from([0xa9, 0x14]), h, Buffer.from([0x87])]),
        redeemScript: inner.script,
        type: `P2SH(${inner.type})`,
      };
    }

    case 'wsh': {
      const inner = compileRedeemScript(node.child, index, chain);
      if (!inner) return null;
      const h = sha256(inner.script);
      return {
        script: Buffer.concat([Buffer.from([0x00, 0x20]), h]),
        witnessScript: inner.script,
        type: `P2WSH(${inner.type})`,
      };
    }

    default:
      return compileRedeemScript(node, index, chain);
  }
}

// isTapscript: when true uses x-only keys (32 bytes) and no OP_DROP in older/after
function compileRedeemScript(node, index = 0, chain = 0, isTapscript = false) {
  switch (node.type) {
    case 'wpkh': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      const h = hash160(pk);
      return { script: Buffer.concat([Buffer.from([0x00, 0x14]), h]), type: 'P2WPKH' };
    }

    case 'wsh': {
      const inner = compileRedeemScript(node.child, index, chain);
      if (!inner) return null;
      const h = sha256(inner.script);
      return {
        script: Buffer.concat([Buffer.from([0x00, 0x20]), h]),
        witnessScript: inner.script,
        type: `P2WSH(${inner.type})`,
      };
    } 

    case 'multi':
    case 'sortedmulti': {
      const pubkeys = node.keys.map(k => derivePublicKey(k, index, chain)).filter(Boolean);
      if (node.type === 'sortedmulti') pubkeys.sort(Buffer.compare);
      const parts = [Buffer.from([0x50 + node.k])];
      for (const pk of pubkeys) parts.push(Buffer.from([0x21]), pk);
      parts.push(Buffer.from([0x50 + pubkeys.length]));
      parts.push(Buffer.from([0xae]));
      return { script: Buffer.concat(parts), type: `MULTI(${node.k}/${pubkeys.length})` };
    }

    case 'thresh': {
      // If all children are bare pk/pk_k (no wrapper), use classic OP_CHECKMULTISIG
      const allBarePk = node.children.every(c => c.type === 'pk' || c.type === 'pk_k');
      if (allBarePk) {
        const pubkeys = node.children.map(c => derivePublicKey(c.key, index, chain)).filter(Boolean);
        const parts = [Buffer.from([0x50 + node.k])];
        for (const pk of pubkeys) {
          const keyBuf = isTapscript ? pk.slice(1) : pk;
          parts.push(Buffer.from([keyBuf.length]), keyBuf);
        }
        parts.push(Buffer.from([0x50 + pubkeys.length]));
        parts.push(Buffer.from([0xae]));
        return { script: Buffer.concat(parts), type: `THRESH(${node.k}/${pubkeys.length})` };
      }
      // Miniscript thresh — correct encoding:
      // compile(X0) compile(X1) OP_ADD compile(X2) OP_ADD ... <k> OP_EQUAL
      const subs = node.children.map(c => compileRedeemScript(c, index, chain, isTapscript));
      if (subs.some(s => !s)) return null;
      const parts2 = [];
      parts2.push(subs[0].script);
      for (let i = 1; i < subs.length; i++) {
        parts2.push(subs[i].script);
        parts2.push(Buffer.from([0x93])); // OP_ADD
      }
      parts2.push(pushScriptInt(node.k));
      parts2.push(Buffer.from([0x87])); // OP_EQUAL
      return { script: Buffer.concat(parts2), type: `THRESH(${node.k}/${node.children.length})` };
    }

    case 'pk':
    case 'pk_k': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      if (isTapscript) {
        // Tapscript: x-only pubkey (32 bytes) + OP_CHECKSIG
        const xOnly = pk.slice(1);
        return { script: Buffer.concat([Buffer.from([0x20]), xOnly, Buffer.from([0xac])]), type: 'PK' };
      }
      return { script: Buffer.concat([Buffer.from([0x21]), pk, Buffer.from([0xac])]), type: 'PK' };
    }

    case 'pkh':
    case 'pk_h': {
      const pk = derivePublicKey(node.key, index, chain);
      if (!pk) return null;
      const h = hash160(pk);
      // In miniscript context, pkh(key) = OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
      return { script: Buffer.concat([Buffer.from([0x76,0xa9,0x14]),h,Buffer.from([0x88,0xac])]), type: 'PKH' };
    }

    case 'older': {
      const nBuf = encodeScriptNum(node.value);
      // Miniscript segwit/tapscript: no OP_DROP — just <n> OP_CSV
      // (OP_DROP was only used in legacy P2SH; in miniscript type V, CSV
      //  consumes the stack via and_v/wrapper v:, no DROP needed)
      return { script: Buffer.concat([pushData(nBuf), Buffer.from([0xb2])]), type: `OLDER(${node.value})` };
    }

    case 'after': {
      const nBuf = encodeScriptNum(node.value);
      // Miniscript segwit/tapscript: sem OP_DROP — apenas <n> OP_CLTV
      return { script: Buffer.concat([pushData(nBuf), Buffer.from([0xb1])]), type: `AFTER(${node.value})` };
    }

    // ── Wrappers ──────────────────────────────────────────────────────────────
    case 'wrapped': {
      const child = compileRedeemScript(node.child, index, chain, isTapscript);
      if (!child) return null;
      let script = child.script;

      // Aplica wrappers da direita para a esquerda (ordem inversa da string)
      for (const w of (node.wrappers || []).reverse()) {
        switch (w) {
          case 'v': {
            // Transform last opcode into VERIFY version, or append OP_VERIFY
            const last = script[script.length - 1];
            if (last === 0xac) {       // OP_CHECKSIG → OP_CHECKSIGVERIFY
              script = Buffer.concat([script.slice(0,-1), Buffer.from([0xad])]);
            } else if (last === 0xae) { // OP_CHECKMULTISIG → OP_CHECKMULTISIGVERIFY
              script = Buffer.concat([script.slice(0,-1), Buffer.from([0xaf])]);
            } else if (last === 0x87) { // OP_EQUAL → OP_EQUALVERIFY
              script = Buffer.concat([script.slice(0,-1), Buffer.from([0x88])]);
            } else {
              script = Buffer.concat([script, Buffer.from([0x69])]); // OP_VERIFY
            }
            break;
          }
          case 's': {
            // OP_SWAP before child script
            script = Buffer.concat([Buffer.from([0x7c]), script]);
            break;
          }
          case 'a': {
            // OP_TOALTSTACK <script> OP_FROMALTSTACK
            script = Buffer.concat([Buffer.from([0x6b]), script, Buffer.from([0x6c])]);
            break;
          }
          case 'c': {
            // Append OP_CHECKSIG at end (used in c:pk_h etc.)
            script = Buffer.concat([script, Buffer.from([0xac])]);
            break;
          }
          case 'd': {
            // OP_DUP OP_IF <script> OP_ENDIF
            script = Buffer.concat([Buffer.from([0x76, 0x63]), script, Buffer.from([0x68])]);
            break;
          }
          case 'j': {
            // OP_SIZE OP_0NOTEQUAL OP_IF <script> OP_ENDIF
            script = Buffer.concat([Buffer.from([0x82, 0x92, 0x63]), script, Buffer.from([0x68])]);
            break;
          }
          case 'n': {
            // <script> OP_0NOTEQUAL
            script = Buffer.concat([script, Buffer.from([0x92])]);
            break;
          }
          case 'l': {
            // OP_IF OP_0 OP_ELSE <script> OP_ENDIF
            script = Buffer.concat([Buffer.from([0x63, 0x00, 0x67]), script, Buffer.from([0x68])]);
            break;
          }
          case 'u': {
            // OP_IF <script> OP_ELSE OP_0 OP_ENDIF
            script = Buffer.concat([Buffer.from([0x63]), script, Buffer.from([0x67, 0x00, 0x68])]);
            break;
          }
          // unknown wrappers: silently ignore
        }
      }
      return { script, type: `WRAP(${child.type})` };
    }

    // ── Miniscript combinators ────────────────────────────────────────────────
    case 'and_v': {
      // and_v(X, Y): concatenate scripts of X and Y
      const x = compileRedeemScript(node.left, index, chain, isTapscript);
      const y = compileRedeemScript(node.right, index, chain, isTapscript);
      if (!x || !y) return null;
      return { script: Buffer.concat([x.script, y.script]), type: 'AND_V' };
    }

    case 'and_b': {
      const x = compileRedeemScript(node.left, index, chain, isTapscript);
      const y = compileRedeemScript(node.right, index, chain, isTapscript);
      if (!x || !y) return null;
      return { script: Buffer.concat([x.script, y.script, Buffer.from([0x9b])]), type: 'AND_B' };
    }

    case 'or_b': {
      const x = compileRedeemScript(node.left, index, chain, isTapscript);
      const y = compileRedeemScript(node.right, index, chain, isTapscript);
      if (!x || !y) return null;
      return { script: Buffer.concat([x.script, y.script, Buffer.from([0x9c])]), type: 'OR_B' };
    }

    case 'or_d': {
      const x = compileRedeemScript(node.left, index, chain, isTapscript);
      const y = compileRedeemScript(node.right, index, chain, isTapscript);
      if (!x || !y) return null;
      return { script: Buffer.concat([Buffer.from([0x73]), x.script, Buffer.from([0x74,0x68]), y.script]), type: 'OR_D' };
    }

    case 'or_i': {
      const x = compileRedeemScript(node.left, index, chain, isTapscript);
      const y = compileRedeemScript(node.right, index, chain, isTapscript);
      if (!x || !y) return null;
      return { script: Buffer.concat([Buffer.from([0x63]), x.script, Buffer.from([0x67]), y.script, Buffer.from([0x68])]), type: 'OR_I' };
    }

    case 'andor': {
      const x = compileRedeemScript(node.x, index, chain, isTapscript);
      const y = compileRedeemScript(node.y, index, chain, isTapscript);
      const z = compileRedeemScript(node.z, index, chain, isTapscript);
      if (!x || !y || !z) return null;
      // andor(X,Y,Z) encoding: X OP_NOTIF Z OP_ELSE Y OP_ENDIF  (Z and Y are swapped!)
      return { script: Buffer.concat([x.script, Buffer.from([0x64]), z.script, Buffer.from([0x67]), y.script, Buffer.from([0x68])]), type: 'ANDOR' };
    }

    default:
      return null;
  }
}

function encodeScriptNum(n) {
  if (n === 0) return Buffer.alloc(0);
  const result = [];
  let abs = Math.abs(n);
  while (abs > 0) { result.push(abs & 0xff); abs >>= 8; }
  if (result[result.length - 1] & 0x80) result.push(n < 0 ? 0x80 : 0x00);
  else if (n < 0) result[result.length - 1] |= 0x80;
  return Buffer.from(result);
}

// Push integers in scripts: values 1-16 use OP_1..OP_16 (0x51..0x60)
// value 0 uses OP_0 (0x00), rest uses pushData(encodeScriptNum)
function pushScriptInt(n) {
  if (n === 0) return Buffer.from([0x00]); // OP_0
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]); // OP_1..OP_16
  return pushData(encodeScriptNum(n));
}

function pushData(buf) {
  if (buf.length <= 75) return Buffer.concat([Buffer.from([buf.length]), buf]);
  if (buf.length <= 255) return Buffer.concat([Buffer.from([0x4c, buf.length]), buf]);
  return Buffer.concat([Buffer.from([0x4d, buf.length & 0xff, buf.length >> 8]), buf]);
}

// ─── ADDRESS DERIVATION ──────────────────────────────────────────────────────
function scriptToAddress(compiled, hrp = 'bc') {
  if (!compiled || !compiled.script || !compiled.script.length) return null;
  const s = compiled.script;

  // P2WPKH: OP_0 <20>
  if (s.length === 22 && s[0] === 0x00 && s[1] === 0x14)
    return witnessToAddress(s.slice(2), 0, hrp);

  // P2WSH: OP_0 <32>
  if (s.length === 34 && s[0] === 0x00 && s[1] === 0x20)
    return witnessToAddress(s.slice(2), 0, hrp);

  // P2TR: OP_1 <32>
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20)
    return witnessToAddress(s.slice(2), 1, hrp);

  // P2SH: OP_HASH160 <20> OP_EQUAL
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) {
    const h    = s.slice(2, 22);
    const full = Buffer.concat([Buffer.from([0x05]), h]);
    return b58CheckEncode(full);
  }

  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[24] === 0xac) {
    const h    = s.slice(3, 23);
    const full = Buffer.concat([Buffer.from([0x00]), h]);
    return b58CheckEncode(full);
  }

  return null;
}

function b58CheckEncode(buf) {
  const checksum = sha256d(buf).slice(0, 4);
  const full     = Buffer.concat([buf, checksum]);
  let   n        = BigInt('0x' + full.toString('hex'));
  let   str      = '';
  while (n > 0n) { str = B58[Number(n % 58n)] + str; n /= 58n; }
  for (let i = 0; i < buf.length && buf[i] === 0; i++) str = '1' + str;
  return str;
}

// ─── FULL ANALYSIS ───────────────────────────────────────────────────────────
// opts: { hrp, deriveSpec: [{index, chain}] }
function analyzeDescriptor(descriptorStr, opts = {}) {
  const clean = tokenizeDescriptor(descriptorStr);
  const node  = parseNode(clean);

  const result = {
    raw:        descriptorStr,
    parsed:     node,
    scriptType: detectScriptType(node),
    keys:       collectKeys(node),
    miniscript: isMiniscript(node),
    addresses:  [],
    errors:     [],
    _hrp:       opts.hrp || 'bc',
    _deriveSpec: opts.deriveSpec || [{ index: 0, chain: 0 }],
  };

  // Derive addresses — accepts { index, chain } or just index (compatibility)
  const deriveSpec = result._deriveSpec || [{ index: 0, chain: 0 }];
  for (const spec of deriveSpec) {
    const idx = typeof spec === 'number' ? spec : spec.index;
    const chn = typeof spec === 'number' ? 0    : (spec.chain || 0);
    try {

    // addr() support — single fixed address
    if (node.type === 'addr') {
      const address = node.address;

      result.addresses.push({
        index: idx,
        chain: chn,
        address,
        scriptType: 'ADDRESS',
        scriptHex: addressToScript(address),
      });

      continue; // pula compileScript
    }

      const compiled = compileScript(node, idx, chn);
      if (compiled) {
        const address = scriptToAddress(compiled, result._hrp || 'bc');
        if (address) {
          result.addresses.push({
            index:       idx,
            chain:       chn,
            address,
            scriptType:  compiled.type,
            scriptHex:   compiled.script.toString('hex'),
            witnessScript: compiled.witnessScript?.toString('hex'),
            redeemScript:  compiled.redeemScript?.toString('hex'),
          });
        }
      }
    } catch(e) {
      result.errors.push(`chain${chn}/${idx}: ${e.message}`);
    }
  }
  delete result._deriveSpec;
  delete result._hrp;

  return result;
}

function addressToScript(address) {
  // P2PKH (1...)
  if (/^1/.test(address)) {
    const payload = b58CheckDecode(address);
    const hash = payload.slice(1);
    return Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      hash,
      Buffer.from([0x88, 0xac])
    ]).toString('hex');
  }

  // P2SH (3...)
  if (/^3/.test(address)) {
    const payload = b58CheckDecode(address);
    const hash = payload.slice(1);
    return Buffer.concat([
      Buffer.from([0xa9, 0x14]),
      hash,
      Buffer.from([0x87])
    ]).toString('hex');
  }

  // Bech32 (bc1 / tb1)
  if (/^(bc1|tb1)/.test(address)) {
    const { version, program } = decodeBech32(address);

    return Buffer.concat([
      Buffer.from([version === 0 ? 0x00 : version + 0x50]),
      Buffer.from([program.length]),
      Buffer.from(program)
    ]).toString('hex');
  }

  throw new Error('Unsupported address type');
}

function detectScriptType(node) {
  switch(node.type) {
    case 'wpkh':  return 'P2WPKH (native segwit)';
    case 'pkh':   return 'P2PKH (legacy)';
    case 'pk':    return 'P2PK';
    case 'sh':    return node.child?.type === 'wpkh' ? 'P2SH-P2WPKH (wrapped segwit)' : 'P2SH';
    case 'wsh': {
      const ct = node.child?.type;
      if (ct === 'multi' || ct === 'sortedmulti') return `P2WSH Multisig`;
      return 'P2WSH (Miniscript)';
    }
    default:      return node.type?.toUpperCase() || 'Unknown';
  }
}

function collectKeys(node, keys = []) {
  if (!node) return keys;
  if (node.key)  keys.push(node.key);
  if (node.keys) node.keys.forEach(k => keys.push(k));
  ['child','left','right','x','y','z','scriptTree'].forEach(f => { if (node[f]) collectKeys(node[f], keys); });
  if (node.children) node.children.forEach(c => collectKeys(c, keys));
  return keys;
}

function isMiniscript(node) {
  const msTypes = ['thresh','and_v','and_b','and_n','or_b','or_c','or_d','or_i','andor','older','after','sha256','hash256','ripemd160','hash160'];
  function check(n) {
    if (!n) return false;
    if (msTypes.includes(n.type)) return true;
    return ['child','left','right','x','y','z','scriptTree'].some(f => check(n[f])) ||
           (n.children || []).some(check);
  }
  return check(node);
}

// ─── SCRIPT HASH for Electrum ───────────────────────────────────────────────
function scriptToScriptHash(scriptHex) {
  const buf = Buffer.from(scriptHex, 'hex');
  return crypto.createHash('sha256').update(buf).digest().reverse().toString('hex');
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────
module.exports = {
  analyzeDescriptor,
  compileRedeemScript,
  parseKeyExpression,
  ExtendedKey,
  derivePublicKey,
  compileScript,
  scriptToAddress,
  scriptToScriptHash,
  parseNode,
};

// ─── CLI (node descriptor-parser.js "<descriptor>" [options]) ──────────────────
// Options:
//   --range <start> <end>    derive indices from <start> to <end> inclusive  (default: 0 0)
//   --index <n> [n2 ...]     derive specific indices
//   --change                 use chain 1 (change) instead of chain 0 (receive)
//
// Exemplos:
//   node descriptor-parser.js "wsh(...)" --range 0 9
//   node descriptor-parser.js "wsh(...)" --index 1 5 10
//   node descriptor-parser.js "wsh(...)" --range 0 4 --change
if (require.main === module) {
  const argv = process.argv.slice(2);

  // Extrai flags
  let descriptor = '';
  let deriveSpec  = null;
  let chain       = 0;

  const args = [...argv];
  // --change
  const changeIdx = args.indexOf('--change');
  if (changeIdx >= 0) { chain = 1; args.splice(changeIdx, 1); }

  // --range <a> <b>
  const rangeIdx = args.indexOf('--range');
  if (rangeIdx >= 0) {
    const start = parseInt(args[rangeIdx + 1]);
    const end   = parseInt(args[rangeIdx + 2]);
    if (isNaN(start) || isNaN(end)) {
      console.error('❌ --range requires two numbers: --range <start> <end>');
      process.exit(1);
    }
    deriveSpec = [];
    for (let i = start; i <= end; i++) deriveSpec.push({ index: i, chain });
    args.splice(rangeIdx, 3);
  }

  // --index <n> [n2 ...]
  const indexIdx = args.indexOf('--index');
  if (indexIdx >= 0) {
    deriveSpec = [];
    let i = indexIdx + 1;
    while (i < args.length && /^\d+$/.test(args[i])) {
      deriveSpec.push({ index: parseInt(args[i]), chain });
      i++;
    }
    if (!deriveSpec.length) {
      console.error('❌ --index requires at least one number: --index 0 1 2');
      process.exit(1);
    }
    args.splice(indexIdx, 1 + deriveSpec.length);
  }

  descriptor = args.join(' ').trim();

  if (!descriptor) {
    console.log(`
Usage: node descriptor-parser.js "<descriptor>" [options]

Options:
  --range <start> <end>     derive indices from start to end  (e.g. --range 0 9)
  --index <n> [n2 ...]      derive specific indices           (e.g. --index 0 1 5)
  --change                  use chain 1 (change)

Exemplos:
  node descriptor-parser.js "wpkh([xxxxxxxxx/84'/0'/0']xpub.../0/*)" --range 0 4
  node descriptor-parser.js "wsh(multi(2,...))" --range 0 9
  node descriptor-parser.js "wsh(...)" --index 0 1 2 --change
`);
    process.exit(0);
  }

  // Default: index 0 if no option was passed
  if (!deriveSpec) deriveSpec = [{ index: 0, chain }];

  try {
    const result = analyzeDescriptor(descriptor, { deriveSpec });

    console.log('\n' + '═'.repeat(60));
    console.log(' DESCRIPTOR ANALYSIS');
    console.log('═'.repeat(60));
    console.log(`\n Tipo:       ${result.scriptType}`);
    console.log(` Miniscript:  ${result.miniscript ? 'Yes ✅' : 'No'}`);
    console.log(` Chaves:     ${result.keys.length}`);

    result.keys.forEach((k, i) => {
      console.log(`\n ─ Chave ${i + 1}`);
      if (k.origin) console.log(`   Fingerprint: [${k.origin.fingerprint}/${k.origin.path}]`);
      console.log(`   Tipo:        ${k.type}`);
      console.log(`   Chave:       ${k.keyStr.slice(0, 20)}…`);
      if (k.derivPath) console.log(`   DerivPath:   /${k.derivPath}`);
    });

    if (result.addresses.length) {
      const chainLabel = chain === 1 ? 'change (chain 1)' : 'recebimento (chain 0)';
      const idxLabel   = deriveSpec.map(s => s.index).join(', ');
      console.log('\n' + '─'.repeat(60));
      console.log(` DERIVED ADDRESSES — ${chainLabel} — indices: ${idxLabel}`);
      console.log('─'.repeat(60));
      result.addresses.forEach(a => {
        console.log(`\n [${a.index}] ${a.address}`);
        console.log(`     Tipo:    ${a.scriptType}`);
        console.log(`     Script:  ${a.scriptHex}`);
        console.log(`     ScriptHash (Electrum): ${scriptToScriptHash(a.scriptHex)}`);
        if (a.witnessScript) console.log(`     WitnessScript: ${a.witnessScript}`);
        if (a.redeemScript)  console.log(`     RedeemScript:  ${a.redeemScript}`);
      });
    }

    if (result.errors.length) {
      console.log('\n Erros:');
      result.errors.forEach(e => console.log(`  ⚠ ${e}`));
    }

    console.log('\n' + '═'.repeat(60) + '\n');
  } catch(e) {
    console.error('\n ❌ Erro ao parsear descritor:', e.message, '\n');
    process.exit(1);
  }
}