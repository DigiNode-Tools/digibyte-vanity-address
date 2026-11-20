// Runs the search across several workers, and checks any match.

import { KINDS, type AddressKind, type Network } from "./chains.ts";
import { addOffset, address, randomKey } from "./keys.ts";
import { addressMatches, patternValues, type Mode } from "./pattern.ts";
import type { StartMessage, WorkerReply } from "./worker.ts";

declare const WORKER_SOURCE: string;

export interface SearchOptions {
  kind: AddressKind;
  net: Network;
  mode: Mode;
  pattern: string;
  threads: number;
}

export interface SearchEvents {
  progress(checked: number, keysPerSecond: number): void;
  found(key: Uint8Array, addr: string, checked: number): void;
  failed(message: string): void;
}

export class Search {
  private workers: Worker[] = [];
  private starts: Uint8Array[] = [];
  private counts: number[] = [];
  private url = "";
  private started = 0;
  private stopped = false;

  constructor(
    private opts: SearchOptions,
    private on: SearchEvents,
  ) {}

  start(): void {
    this.url = URL.createObjectURL(new Blob([WORKER_SOURCE], { type: "text/javascript" }));
    this.started = performance.now();
    for (let i = 0; i < this.opts.threads; i++) {
      const start = randomKey();
      this.starts.push(start);
      this.counts.push(0);
      const w = new Worker(this.url);
      w.onmessage = (e: MessageEvent<WorkerReply>) => this.reply(i, e.data);
      w.onerror = (e) => this.fail(e.message || "a search thread stopped");
      const msg: StartMessage = {
        kind: KINDS[this.opts.kind].code,
        mode: this.opts.mode === "prefix" ? 0 : 1,
        pattern: patternValues(this.opts.pattern),
        hrp: this.opts.net.hrp,
        start: start.slice(),
      };
      w.postMessage(msg);
      this.workers.push(w);
    }
  }

  stop(): void {
    this.stopped = true;
    for (const w of this.workers) w.terminate();
    this.workers = [];
    for (const s of this.starts) s.fill(0);
    this.starts = [];
    if (this.url) URL.revokeObjectURL(this.url);
  }

  private total(): number {
    return this.counts.reduce((a, b) => a + b, 0);
  }

  private reply(i: number, m: WorkerReply): void {
    if (this.stopped) return;
    if (m.type === "error") return this.fail(m.message);
    this.counts[i] = m.checked;
    const seconds = (performance.now() - this.started) / 1000;
    this.on.progress(this.total(), seconds > 0 ? this.total() / seconds : 0);
    if (m.type !== "found") return;

    // Work out the key ourselves and check it with a separate library.
    const key = addOffset(this.starts[i], BigInt(m.offset));
    const addr = address(key, this.opts.kind, this.opts.net);
    const total = this.total();
    this.stop();
    if (!addressMatches(addr, this.opts.kind, this.opts.net, this.opts.mode, this.opts.pattern)) {
      key.fill(0);
      this.on.failed("A check failed, so no address was shown. Please try again, and tell us if it keeps happening.");
      return;
    }
    this.on.found(key, addr, total);
  }

  private fail(message: string): void {
    if (this.stopped) return;
    this.stop();
    this.on.failed(message);
  }
}
