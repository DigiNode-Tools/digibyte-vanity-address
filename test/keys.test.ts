import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { NETWORKS, type Network } from "../src/chains.ts";
import { addOffset, address, bigIntToBytes, descriptor, descriptorChecksum, N, randomKey, witnessProgram, wif } from "../src/keys.ts";
import { addressMatches, checkPattern, patternValues } from "../src/pattern.ts";

const BITCOIN: Network = { id: "btc", name: "Bitcoin", ticker: "BTC", hrp: "bc", wif: 128, testnet: false };
const DGB = NETWORKS[0];
const DGBT = NETWORKS[1];
const one = bigIntToBytes(1n);

describe("well-known vectors", () => {
  it("private key 1", () => {
    expect(address(one, "segwit", BITCOIN)).toBe("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    expect(wif(one, BITCOIN)).toBe("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
  });

  it("descriptor checksums (Bitcoin Core doc/descriptors.md)", () => {
    expect(descriptorChecksum("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)")).toBe("02wpgw69");
    expect(descriptorChecksum("raw(deadbeef)")).toBe("89f8spxm");
  });

  it("DigiByte prefixes", () => {
    expect(address(one, "segwit", DGB).startsWith("dgb1q")).toBe(true);
    expect(address(one, "taproot", DGB).startsWith("dgb1p")).toBe(true);
    expect(address(one, "segwit", DGBT).startsWith("dgbt1q")).toBe(true);
    expect(wif(one, DGB)).toBe(wif(one, BITCOIN)); // DigiByte uses 128, like Bitcoin
    expect(descriptor(one, "segwit", DGB)).toMatch(/^wpkh\(K[1-9A-HJ-NP-Za-km-z]{51}\)#[a-z0-9]{8}$/);
    expect(descriptor(one, "taproot", DGB)).toMatch(/^tr\(K/);
  });

  it("keys wrap around the group order", () => {
    expect(addOffset(bigIntToBytes(N - 1n), 2n)).toEqual(one);
  });
});

describe("patterns", () => {
  it("accepts only address characters", () => {
    expect(checkPattern("DGNode").ok).toBe(false); // has "o"
    expect(checkPattern("DGNDE").ok).toBe(true);
    expect(checkPattern("DGNDE").text).toBe("dgnde");
    expect(checkPattern("b1").bad).toEqual(["b", "1"]);
  });
});

// The WebAssembly search, loaded the same way the page loads it.
const wasmBytes = readFileSync(new URL("../wasm/target/wasm32-unknown-unknown/release/vanity_search.wasm", import.meta.url));

async function loadWasm() {
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  const w = instance.exports as any;
  const io = () => new Uint8Array(w.memory.buffer, w.io_ptr(), 256);
  return { w, io };
}

describe("WebAssembly agrees with the JavaScript code", () => {
  it("gives the same witness program for 300 random keys", async () => {
    const { w, io } = await loadWasm();
    for (let i = 0; i < 300; i++) {
      const key = randomKey();
      for (const kind of ["segwit", "taproot"] as const) {
        io().set(key, 0);
        const len = w.program_for_key(kind === "segwit" ? 0 : 1);
        expect(io().slice(0, len)).toEqual(witnessProgram(key, kind));
      }
    }
  });

  it("finds keys whose addresses really match", async () => {
    const { w, io } = await loadWasm();
    for (const kind of ["segwit", "taproot"] as const) {
      for (const mode of ["prefix", "suffix"] as const) {
        for (const net of [DGB, DGBT]) {
          const text = "dg";
          const start = randomKey();
          const b = io();
          b.set(start, 0);
          b.set(patternValues(text), 32);
          b.set(new TextEncoder().encode(net.hrp), 128);
          expect(w.init(kind === "segwit" ? 0 : 1, mode === "prefix" ? 0 : 1, text.length, net.hrp.length)).toBe(0);
          let rc = 0;
          for (let i = 0; i < 1000 && rc === 0; i++) rc = w.run(1);
          expect(rc).toBe(1);
          let offset = 0n;
          for (let i = 7; i >= 0; i--) offset = (offset << 8n) | BigInt(io()[i]);
          const addr = address(addOffset(start, offset), kind, net);
          expect(addressMatches(addr, kind, net, mode, text), `${addr} ${mode}`).toBe(true);
        }
      }
    }
  });
});
