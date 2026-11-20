// Search worker. Runs the WebAssembly search on its own CPU thread.
//
// It receives a start key, a pattern and the address type, and reports only
// how many keys it has checked and, when it finds a match, the offset of
// that key from the start. It never sends a private key back: the page
// already knows the start key and works the private key out itself.

declare const WASM_BASE64: string;

interface Wasm {
  memory: WebAssembly.Memory;
  io_ptr(): number;
  init(kind: number, mode: number, plen: number, hlen: number): number;
  run(batches: number): number;
  checked_lo(): number;
  checked_hi(): number;
}

export interface StartMessage {
  kind: number;
  mode: number;
  pattern: number[];
  hrp: string;
  start: Uint8Array;
}

export type WorkerReply =
  | { type: "progress"; checked: number }
  | { type: "found"; checked: number; offset: string }
  | { type: "error"; message: string };

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const ctx = self as unknown as {
  postMessage(m: WorkerReply): void;
  onmessage: ((e: MessageEvent<StartMessage>) => void) | null;
};

ctx.onmessage = async (e) => {
  try {
    const module = await WebAssembly.compile(decodeBase64(WASM_BASE64) as Uint8Array<ArrayBuffer>);
    const instance = await WebAssembly.instantiate(module, {});
    const w = instance.exports as unknown as Wasm;
    const msg = e.data;
    const io = () => new Uint8Array(w.memory.buffer, w.io_ptr(), 256);
    const buf = io();
    buf.set(msg.start, 0);
    buf.set(msg.pattern, 32);
    buf.set(new TextEncoder().encode(msg.hrp), 128);
    msg.start.fill(0);
    const rc = w.init(msg.kind, msg.mode, msg.pattern.length, msg.hrp.length);
    buf.fill(0, 0, 32);
    if (rc !== 0) throw new Error(`search could not start (${rc})`);

    const checked = () => w.checked_hi() * 2 ** 32 + w.checked_lo();
    // Taproot keys are ~40x slower, so do fewer per step to keep progress smooth.
    const step = msg.kind === 0 ? 64 : 2;
    let last = 0;
    for (;;) {
      if (w.run(step) === 1) {
        const b = io();
        let offset = 0n;
        for (let i = 7; i >= 0; i--) offset = (offset << 8n) | BigInt(b[i]);
        ctx.postMessage({ type: "found", checked: checked(), offset: offset.toString() });
        return;
      }
      const now = performance.now();
      if (now - last > 250) {
        last = now;
        ctx.postMessage({ type: "progress", checked: checked() });
      }
    }
  } catch (err) {
    ctx.postMessage({ type: "error", message: String(err) });
  }
};
