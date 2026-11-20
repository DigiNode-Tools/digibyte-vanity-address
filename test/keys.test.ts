import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { NETWORKS, type Network } from "../src/chains.ts";
import { addOffset, address, bigIntToBytes, descriptor, descriptorChecksum, N, randomKey, witnessProgram, wif } from "../src/keys.ts";
import { addressMatches, checkPattern, expectedTries, patternValues } from "../src/pattern.ts";

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

describe("estimates", () => {
  it("anywhere counts every position after the fixed start", () => {
    // SegWit: 38 characters after dgb1q, so a 6-letter word fits in 33 places.
    expect(expectedTries(6, "anywhere", "segwit")).toBe(Math.ceil(32 ** 6 / 33));
    expect(expectedTries(6, "prefix", "segwit")).toBe(32 ** 6);
    // Taproot: 58 characters after dgb1p.
    expect(expectedTries(6, "anywhere", "taproot")).toBe(Math.ceil(32 ** 6 / 53));
  });
  it("anywhere matches the start, the middle and the checksum", () => {
    const a = address(bigIntToBytes(9n), "segwit", DGB);
    const rest = a.slice(5);
    for (let i = 0; i + 4 <= rest.length; i++) expect(addressMatches(a, "segwit", DGB, "anywhere", rest.slice(i, i + 4))).toBe(true);
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
      for (const mode of ["prefix", "suffix", "anywhere"] as const) {
        for (const net of [DGB, DGBT]) {
          const text = "dg";
          const start = randomKey();
          const b = io();
          b.set(start, 0);
          b.set(patternValues(text), 32);
          b.set(new TextEncoder().encode(net.hrp), 128);
          expect(w.init(kind === "segwit" ? 0 : 1, { prefix: 0, suffix: 1, anywhere: 2 }[mode], text.length, net.hrp.length)).toBe(0);
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

describe("DigiByte vectors checked against DigiByte Core v9.26.7 deriveaddresses (2026-11-20)", () => {
  const cases = [
    { key: 1n, net: DGB, kind: "segwit" as const, addr: "dgb1qw508d6qejxtdg4y5r3zarvary0c5xw7kmudfnm", desc: "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)#gul0776m" },
    { key: 1n, net: DGB, kind: "taproot" as const, addr: "dgb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssuuh6f6", desc: "tr(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn)#efdxzarj" },
    { key: 2n, net: DGB, kind: "segwit" as const, addr: "dgb1qq6hag67dl53wl99vzg42z8eyzfz2xlkv3zu020", desc: "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4)#ccxepx3w" },
    { key: 2n, net: DGB, kind: "taproot" as const, addr: "dgb1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9lasxtp40h", desc: "tr(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4)#ppnxgt0v" },
    { key: 3n, net: DGB, kind: "segwit" as const, addr: "dgb1q0ht9tyks4vh7p5p904t340cr9nvahy7uxcax6x", desc: "wpkh(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S)#xlnu28tj" },
    { key: 3n, net: DGB, kind: "taproot" as const, addr: "dgb1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaq0w4nh0", desc: "tr(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S)#d8h3prcv" },
    { key: 1n, net: DGBT, kind: "segwit" as const, addr: "dgbt1qw508d6qejxtdg4y5r3zarvary0c5xw7kwk83wk", desc: "wpkh(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnXacFLhTH)#7t90k7qd" },
    { key: 1n, net: DGBT, kind: "taproot" as const, addr: "dgbt1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sshy64g3", desc: "tr(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnXacFLhTH)#49u3g6gn" },
    { key: 2n, net: DGBT, kind: "segwit" as const, addr: "dgbt1qq6hag67dl53wl99vzg42z8eyzfz2xlkvygkhhz", desc: "wpkh(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnY5T7Ndji)#n8ds0wpd" },
    { key: 2n, net: DGBT, kind: "taproot" as const, addr: "dgbt1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9lasdnv6wu", desc: "tr(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnY5T7Ndji)#wp7sxy5a" },
    { key: 3n, net: DGBT, kind: "segwit" as const, addr: "dgbt1q0ht9tyks4vh7p5p904t340cr9nvahy7unjh78t", desc: "wpkh(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnYaPgZHar)#j8hpvdm8" },
    { key: 3n, net: DGBT, kind: "taproot" as const, addr: "dgbt1pgxxyvcmdncdxs06cudd5yvmwwahaesaj6n3eu7st7x4sw9hrchaqykcuky", desc: "tr(eaHADzXVU3hvWSN7UFFqDD2iDN2h3HseMDE78P13iYRnYaPgZHar)#kturhzvn" },
  ];
  for (const c of cases) {
    it(`${c.net.id} ${c.kind} key ${c.key}`, () => {
      const k = bigIntToBytes(c.key);
      expect(address(k, c.kind, c.net)).toBe(c.addr);
      expect(descriptor(k, c.kind, c.net)).toBe(c.desc);
    });
  }
});
