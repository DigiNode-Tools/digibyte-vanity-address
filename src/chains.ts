// Blockchains and networks this tool can make addresses for.
// Values come from each chain's own source code (chainparams.cpp).
// Adding another chain later (Nito, Litecoin, Bitcoin...) is just another row.

export interface Network {
  /** Short id used in the page, e.g. "dgb". */
  id: string;
  /** Name shown to people. */
  name: string;
  /** Coin ticker. */
  ticker: string;
  /** Bech32 human-readable part, e.g. "dgb" gives "dgb1q..." addresses. */
  hrp: string;
  /** Version byte for WIF private keys. */
  wif: number;
  testnet: boolean;
}

// DigiByte Core src/chainparams.cpp: bech32_hrp "dgb", SECRET_KEY 128 (mainnet);
// bech32_hrp "dgbt", SECRET_KEY 254 (testnet).
export const NETWORKS: Network[] = [
  { id: "dgb", name: "DigiByte", ticker: "DGB", hrp: "dgb", wif: 128, testnet: false },
  { id: "dgbt", name: "DigiByte testnet", ticker: "DGB", hrp: "dgbt", wif: 254, testnet: true },
];

export type AddressKind = "segwit" | "taproot";

export const KINDS: Record<AddressKind, { code: number; version: number; label: string; versionChar: string }> = {
  // Native SegWit v0, P2WPKH: hrp + "1q" + ...
  segwit: { code: 0, version: 0, label: "SegWit", versionChar: "q" },
  // Taproot, BIP86 key path: hrp + "1p" + ...
  taproot: { code: 1, version: 1, label: "Taproot", versionChar: "p" },
};

/** Characters a bech32 address can contain, in value order (0-31). */
export const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
