// Private keys, addresses and descriptors, using audited libraries
// (@noble/curves, @noble/hashes, @scure/base). This is a separate
// implementation from the WebAssembly search, and every match the search
// reports is rebuilt and checked here before anything is shown.

import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { bech32, bech32m, createBase58check } from "@scure/base";
import { KINDS, type AddressKind, type Network } from "./chains.ts";

const Point = secp256k1.Point;
/** Order of the secp256k1 group: valid private keys are 1 .. N-1. */
export const N = Point.CURVE().n;

const base58check = createBase58check(sha256);

export function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function bigIntToBytes(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** A random private key from the browser's cryptographic random generator. */
export function randomKey(): Uint8Array {
  for (;;) {
    const k = new Uint8Array(32);
    crypto.getRandomValues(k);
    const v = bytesToBigInt(k);
    if (v > 0n && v < N) return k;
  }
}

/** Private key `start + offset`, as 32 bytes. */
export function addOffset(start: Uint8Array, offset: bigint): Uint8Array {
  const v = (bytesToBigInt(start) + offset) % N;
  if (v === 0n) throw new Error("invalid key");
  return bigIntToBytes(v);
}

export function hash160(b: Uint8Array): Uint8Array {
  return ripemd160(sha256(b));
}

/** The witness program for a private key: 20 bytes (SegWit) or 32 (Taproot). */
export function witnessProgram(key: Uint8Array, kind: AddressKind): Uint8Array {
  const d = bytesToBigInt(key);
  if (d <= 0n || d >= N) throw new Error("invalid key");
  const P = Point.BASE.multiply(d);
  if (kind === "segwit") return hash160(P.toBytes(true));
  // BIP86: output key Q = lift_x(x(P)) + H_TapTweak(x(P))·G, program = x(Q).
  const x = P.toBytes(true).slice(1);
  const internal = schnorr.utils.lift_x(bytesToBigInt(x));
  const t = bytesToBigInt(schnorr.utils.taggedHash("TapTweak", x));
  if (t >= N) throw new Error("invalid tweak");
  const Q = internal.add(Point.BASE.multiply(t));
  return Q.toBytes(true).slice(1);
}

export function address(key: Uint8Array, kind: AddressKind, net: Network): string {
  const program = witnessProgram(key, kind);
  const { version } = KINDS[kind];
  const coder = version === 0 ? bech32 : bech32m;
  return coder.encode(net.hrp, [version, ...coder.toWords(program)]);
}

/** Wallet Import Format for a compressed public key. */
export function wif(key: Uint8Array, net: Network): string {
  const payload = new Uint8Array(34);
  payload[0] = net.wif;
  payload.set(key, 1);
  payload[33] = 1;
  return base58check.encode(payload);
}

// Output descriptor checksum, exactly as in DigiByte/Bitcoin Core
// (src/script/descriptor.cpp, DescriptorChecksum).
const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}" +
  "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
  'ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

function polymod(c: bigint, v: number): bigint {
  const c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(v);
  for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= GENERATOR[i];
  return c;
}

export function descriptorChecksum(desc: string): string {
  let c = 1n;
  let cls = 0;
  let clscount = 0;
  for (const ch of desc) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos < 0) throw new Error("invalid character in descriptor");
    c = polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    if (++clscount === 3) {
      c = polymod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) c = polymod(c, cls);
  for (let i = 0; i < 8; i++) c = polymod(c, 0);
  c ^= 1n;
  let out = "";
  for (let i = 0; i < 8; i++) out += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  return out;
}

/** A descriptor for importing the key into DigiByte Core, e.g. wpkh(WIF)#checksum. */
export function descriptor(key: Uint8Array, kind: AddressKind, net: Network): string {
  const d = `${kind === "segwit" ? "wpkh" : "tr"}(${wif(key, net)})`;
  return `${d}#${descriptorChecksum(d)}`;
}
