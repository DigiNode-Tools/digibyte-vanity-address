import { BECH32_CHARSET, KINDS, type AddressKind, type Network } from "./chains.ts";

export type Mode = "prefix" | "suffix" | "anywhere";

export interface PatternCheck {
  ok: boolean;
  /** Lowercase pattern. */
  text: string;
  /** Characters that can't appear in an address. */
  bad: string[];
  message: string;
}

/** Longest pattern accepted (a 10-character one would take years in a browser). */
export const MAX_LENGTH = 10;

export function checkPattern(input: string): PatternCheck {
  const text = input.trim().toLowerCase();
  const bad = [...new Set([...text].filter((c) => !BECH32_CHARSET.includes(c)))];
  if (!text) return { ok: false, text, bad, message: "Type the letters and numbers you want in your address." };
  if (bad.length) {
    const shown = bad.map((c) => (c === " " ? "spaces" : `"${c}"`)).join(", ");
    return {
      ok: false,
      text,
      bad,
      message: `${shown} can't be used. These addresses never contain b, i, o or 1, and only use lowercase letters and the numbers 0 and 2–9.`,
    };
  }
  if (text.length > MAX_LENGTH) {
    return { ok: false, text, bad, message: `Use ${MAX_LENGTH} characters or fewer.` };
  }
  return { ok: true, text, bad, message: "" };
}

/** The pattern as 5-bit values, for the search. */
export function patternValues(text: string): number[] {
  return [...text].map((c) => BECH32_CHARSET.indexOf(c));
}

/** Characters after the fixed start (e.g. "dgb1q"): the program, then a 6-character checksum. */
export function tailLength(kind: AddressKind): number {
  return kind === "segwit" ? 32 + 6 : 52 + 6;
}

/** Number of places the letters could be: one for first or last, every position for anywhere. */
export function positions(length: number, mode: Mode, kind: AddressKind): number {
  return mode === "anywhere" ? Math.max(1, tailLength(kind) - length + 1) : 1;
}

/** Average number of keys to check before finding a match. */
export function expectedTries(length: number, mode: Mode = "prefix", kind: AddressKind = "segwit"): number {
  return Math.ceil(32 ** length / positions(length, mode, kind));
}

/** Chance of having found a match after checking `tries` keys. */
export function chanceFound(length: number, tries: number, mode: Mode = "prefix", kind: AddressKind = "segwit"): number {
  return 1 - Math.exp(-tries / expectedTries(length, mode, kind));
}

/** The fixed start of every address of this type, e.g. "dgb1q". */
export function addressStart(kind: AddressKind, net: Network): string {
  return `${net.hrp}1${KINDS[kind].versionChar}`;
}

export function addressMatches(addr: string, kind: AddressKind, net: Network, mode: Mode, text: string): boolean {
  const start = addressStart(kind, net);
  if (!addr.startsWith(start)) return false;
  const rest = addr.slice(start.length);
  if (mode === "prefix") return rest.startsWith(text);
  if (mode === "suffix") return rest.endsWith(text);
  return rest.includes(text);
}

/** "about 3 minutes" style time. */
export function friendlyDuration(seconds: number): string {
  if (!isFinite(seconds)) return "a very long time";
  if (seconds < 1) return "under a second";
  const units: [number, string][] = [
    [365 * 24 * 3600, "year"],
    [30 * 24 * 3600, "month"],
    [7 * 24 * 3600, "week"],
    [24 * 3600, "day"],
    [3600, "hour"],
    [60, "minute"],
    [1, "second"],
  ];
  for (const [size, name] of units) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      if (n >= 1000 && name === "year") return "thousands of years";
      return `${n.toLocaleString("en-GB")} ${name}${n === 1 ? "" : "s"}`;
    }
  }
  return "under a second";
}
