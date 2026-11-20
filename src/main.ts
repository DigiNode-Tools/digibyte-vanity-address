// Page logic for DigiByte Vanity Address.

import { NETWORKS, type AddressKind, type Network } from "./chains.ts";
import { descriptor, wif } from "./keys.ts";
import {
  addressStart,
  chanceFound,
  checkPattern,
  expectedTries,
  friendlyDuration,
  type Mode,
} from "./pattern.ts";
import { Search } from "./search.ts";
import qrcodegen from "./vendor/qrcodegen.ts";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const embedded = window.self !== window.top;
if (embedded) document.body.classList.add("embedded");

// Rough single-core speeds, used only for the estimate before a search has run.
// Replaced by the measured speed once a search has run on this device.
const guessPerCore: Record<AddressKind, number> = { segwit: 300_000, taproot: 9_000 };
const measuredPerCore: Partial<Record<AddressKind, number>> = {};

const cores = Math.max(1, navigator.hardwareConcurrency || 2);
const threads = $<HTMLInputElement>("threads");
threads.max = String(cores);
threads.value = String(Math.max(1, cores - 1));

const form = $<HTMLFormElement>("form");
const patternInput = $<HTMLInputElement>("pattern");

let search: Search | null = null;
let startedAt = 0;
let current: { key: Uint8Array; addr: string; kind: AddressKind; net: Network; mode: Mode; text: string } | null = null;

function settings() {
  const data = new FormData(form);
  const kind = data.get("kind") as AddressKind;
  const mode = data.get("mode") as Mode;
  const net = $<HTMLInputElement>("testnet").checked ? NETWORKS[1] : NETWORKS[0];
  return { kind, mode, net, threads: Number(threads.value), check: checkPattern(patternInput.value) };
}

function escape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function speedFor(kind: AddressKind, n: number): number {
  return (measuredPerCore[kind] ?? guessPerCore[kind]) * n;
}

function updateForm(): void {
  const s = settings();
  $("threads-out").textContent = `${s.threads} of ${cores}`;
  for (const k of ["segwit", "taproot"] as const) {
    for (const el of document.querySelectorAll(`.start-${k}`)) el.textContent = `${addressStart(k, s.net)}…`;
  }
  const start = addressStart(s.kind, s.net);
  const text = s.check.text;
  patternInput.setAttribute("aria-invalid", String(!!text && !s.check.ok));
  const preview = $("preview");
  const odds = $("odds");
  odds.classList.remove("slow");
  if (!text) {
    preview.innerHTML = `${start}<mark>…</mark>`;
    odds.textContent = "";
  } else if (!s.check.ok) {
    preview.innerHTML = `<span class="error">${escape(s.check.message)}</span>`;
    odds.textContent = "";
  } else {
    const shown = `<mark>${escape(text)}</mark>`;
    preview.innerHTML = s.mode === "prefix" ? `${start}${shown}…` : `${start}…${shown}`;
    const tries = expectedTries(text.length);
    const seconds = tries / speedFor(s.kind, s.threads);
    odds.textContent = `About 1 in ${tries.toLocaleString("en-GB")} addresses match. On this device that takes about ${friendlyDuration(seconds)}, but you could be lucky or unlucky.`;
    if (seconds > 3600) {
      odds.classList.add("slow");
      odds.textContent += " That's a long time for a web page: try fewer letters.";
    }
  }
}

function setRunning(running: boolean): void {
  $("start").hidden = running;
  $("stop").hidden = !running;
  for (const el of form.querySelectorAll<HTMLInputElement>("input")) el.disabled = running;
}

function showError(message: string): void {
  const e = $("form-error");
  e.textContent = message;
  e.hidden = !message;
}

function startSearch(): void {
  const s = settings();
  if (!s.check.ok) {
    showError(s.check.message);
    patternInput.focus();
    return;
  }
  showError("");
  clearResult();
  const text = s.check.text;
  const opts = { kind: s.kind, net: s.net, mode: s.mode, pattern: text, threads: s.threads };
  startedAt = performance.now();
  $("progress").hidden = false;
  $("st-checked").textContent = "0";
  $("st-speed").textContent = "–";
  $("st-chance").textContent = "0%";
  $<HTMLDivElement>("st-bar").style.width = "0";
  $("st-note").textContent = "";
  setRunning(true);
  search = new Search(opts, {
    progress(checked, perSecond) {
      const secs = (performance.now() - startedAt) / 1000;
      const chance = chanceFound(text.length, checked);
      $("st-checked").textContent = checked.toLocaleString("en-GB");
      $("st-speed").textContent = Math.round(perSecond).toLocaleString("en-GB");
      $("st-time").textContent = friendlyDuration(secs).replace("under a second", "0s");
      $("st-chance").textContent = `${Math.floor(chance * 100)}%`;
      $<HTMLDivElement>("st-bar").style.width = `${Math.min(100, chance * 100)}%`;
      if (secs > 2 && perSecond > 0) {
        measuredPerCore[s.kind] = perSecond / s.threads;
        const left = (expectedTries(text.length) - checked) / perSecond;
        $("st-note").textContent =
          left > 0 ? `On average, a match turns up in about ${friendlyDuration(left)} more.` : "Any moment now…";
      }
    },
    found(key, addr) {
      search = null;
      setRunning(false);
      $("progress").hidden = true;
      current = { key, addr, kind: s.kind, net: s.net, mode: s.mode, text };
      showResult();
    },
    failed(message) {
      search = null;
      setRunning(false);
      $("progress").hidden = true;
      showError(message);
    },
  });
  search.start();
}

function stopSearch(): void {
  search?.stop();
  search = null;
  setRunning(false);
  $("progress").hidden = true;
}

function qrSvg(text: string): string {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const border = 2;
  let path = "";
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) if (qr.getModule(x, y)) path += `M${x + border},${y + border}h1v1h-1z`;
  }
  const size = qr.size + border * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="var(--qr-bg)"/><path d="${path}" fill="var(--qr-fg)"/></svg>`;
}

function highlighted(r: NonNullable<typeof current>): string {
  const start = addressStart(r.kind, r.net);
  const rest = r.addr.slice(start.length);
  const n = r.text.length;
  return r.mode === "prefix"
    ? `${start}<mark>${rest.slice(0, n)}</mark>${rest.slice(n)}`
    : `${start}${rest.slice(0, rest.length - n)}<mark>${rest.slice(rest.length - n)}</mark>`;
}

function showResult(): void {
  if (!current) return;
  $("r-address").innerHTML = highlighted(current);
  $("r-address-qr").innerHTML = qrSvg(current.addr);
  $("key-box").hidden = true;
  $("show-key").textContent = "Show private key";
  $("r-taproot-note").hidden = current.kind !== "taproot";
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: "smooth", block: "start" });
}

function toggleKey(): void {
  if (!current) return;
  const box = $("key-box");
  if (!box.hidden) {
    hideKey();
    return;
  }
  const w = wif(current.key, current.net);
  const desc = descriptor(current.key, current.kind, current.net);
  $("r-wif").textContent = w;
  $("r-wif-qr").innerHTML = qrSvg(w);
  $("r-descriptor").textContent = desc;
  $("r-import").textContent = `importdescriptors '[{"desc":"${desc}","timestamp":"now"}]'`;
  box.hidden = false;
  $("show-key").textContent = "Hide private key";
}

function hideKey(): void {
  for (const id of ["r-wif", "r-wif-qr", "r-descriptor", "r-import"]) $(id).textContent = "";
  $("key-box").hidden = true;
  $("show-key").textContent = "Show private key";
}

function clearResult(): void {
  hideKey();
  current?.key.fill(0);
  current = null;
  $("r-address").textContent = "";
  $("r-address-qr").textContent = "";
  $("result").hidden = true;
  $("copied").hidden = true;
}

async function copy(text: string, what: string): Promise<void> {
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch {
    // Clipboard API may be blocked inside the website's sandboxed frame.
    const area = $<HTMLTextAreaElement>("copy-area");
    area.value = text;
    area.select();
    ok = document.execCommand("copy");
    area.value = "";
  }
  const msg = $("copied");
  msg.textContent = ok ? `${what} copied.` : "Copying isn't allowed here. Select the text and copy it yourself.";
  msg.className = ok ? "status ok" : "status error";
  msg.hidden = false;
}

function download(): void {
  if (!current) return;
  const lines = [
    "DigiByte Vanity Address - KEEP THIS FILE SECRET",
    "",
    `Network:      ${current.net.name}`,
    `Address type: ${current.kind === "segwit" ? "SegWit" : "Taproot"}`,
    `Address:      ${current.addr}`,
    `Private key:  ${wif(current.key, current.net)}`,
    `Descriptor:   ${descriptor(current.key, current.kind, current.net)}`,
    "",
    "Anyone with the private key can spend the coins at this address.",
    "Store this file somewhere safe and offline, or print it and delete the file.",
    "",
  ];
  const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = `dgb-vanity-${current.addr.slice(-8)}.txt`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

form.addEventListener("input", updateForm);
form.addEventListener("change", updateForm);
// The website shows this page in a sandboxed frame where forms can't be
// submitted, so the button and the Enter key are handled directly.
form.addEventListener("submit", (e) => e.preventDefault());
$("start").addEventListener("click", startSearch);
patternInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    if (!search) startSearch();
  }
});
$("stop").addEventListener("click", stopSearch);
$("show-key").addEventListener("click", toggleKey);
$("clear").addEventListener("click", clearResult);
$("again").addEventListener("click", () => {
  clearResult();
  startSearch();
});
$("download").addEventListener("click", download);
for (const b of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
  b.addEventListener("click", () => {
    if (!current) return;
    if (b.dataset.copy === "address") copy(current.addr, "Address");
    else copy(wif(current.key, current.net), "Private key");
  });
}
window.addEventListener("pagehide", () => {
  search?.stop();
  clearResult();
});

// When shown inside diginode.tools: follow the site's light/dark setting,
// and tell the page how tall this frame needs to be. Nothing else is shared.
if (embedded) {
  const theme = new URLSearchParams(location.hash.slice(1)).get("theme");
  if (theme === "dark" || theme === "light") document.documentElement.dataset.theme = theme;
  window.addEventListener("message", (e) => {
    if (e.source !== window.parent) return;
    const t = (e.data as { theme?: unknown })?.theme;
    if (t === "dark" || t === "light") document.documentElement.dataset.theme = t;
  });
  // Measure the content itself: the document's own height never shrinks below the frame's.
  const main = document.querySelector("main")!;
  const post = () =>
    window.parent.postMessage({ type: "dgb-vanity-height", height: Math.ceil(main.getBoundingClientRect().height) + 4 }, "*");
  new ResizeObserver(post).observe(main);
  post();
}

updateForm();
