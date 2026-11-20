# DigiByte Vanity Address

Make a DigiByte address with letters you choose, at the start, the end or anywhere in it, like `dgb1qdgnd…` or `dgb1q…cafe`. It runs entirely in your web browser: your private key is made on your own device and is never sent anywhere.

**Use it at [diginode.tools/digibyte-vanity-address](https://diginode.tools/digibyte-vanity-address/)**, or [download `digibyte-vanity-address.html`](https://github.com/DigiNode-Tools/digibyte-vanity-address/releases/latest/download/digibyte-vanity-address.html) from the [latest release](https://github.com/DigiNode-Tools/digibyte-vanity-address/releases/latest) and open it on a computer that isn't connected to the internet.

Part of [DigiNode Tools](https://diginode.tools).

## What it makes

- **SegWit** addresses (`dgb1q…`): work with almost every DigiByte wallet.
- **Taproot** addresses (`dgb1p…`, BIP86 key path): newer, and slower to search.
- Testnet versions of both (`dgbt1q…`, `dgbt1p…`).

For each address you get the private key in WIF format, QR codes, and a descriptor (`wpkh(…)#checksum` or `tr(…)#checksum`) to import into DigiByte Core with `importdescriptors`.

## How long does it take?

Each extra character makes a match 32 times rarer. On a 10-core laptop, in a browser:

| Characters | SegWit (≈ 2.8 million a second) | Taproot (≈ 58,000 a second) |
|---|---|---|
| 3 | instant | under a second |
| 4 | under a second | about 20 seconds |
| 5 | about 12 seconds | about 10 minutes |
| 6 | about 6 minutes | about 5 hours |
| 7 | about 3 hours | days |

These are averages: you may be lucky or unlucky.

**Letters anywhere is much faster.** If your letters can be anywhere in the address, not just at the start or end, there are many more places they can appear: a 6-letter word fits in 33 places in a SegWit address and 53 in a Taproot one. So it's roughly 30–50 times faster, and 7 or 8 letters become practical in a browser.

## How it keeps your key safe

- **Nothing leaves your device.** The page has a strict Content-Security-Policy (`default-src 'none'; connect-src 'none'`), so it can't load or send anything, even if it wanted to. The search code (WebAssembly) has no imports at all: it can only do arithmetic.
- **Two independent checks.** The fast search is written in Rust (RustCrypto's `k256`, `sha2`, `ripemd`). It only reports *where* it found a match. The page then rebuilds the key and address with separate, audited JavaScript libraries (`@noble/curves`, `@noble/hashes`, `@scure/base`) and only shows a result if both agree.
- **Strong randomness.** Each search thread starts from a random key from `crypto.getRandomValues`, the browser's cryptographic random number generator, then checks the next keys in order.
- **Nothing is stored.** No cookies or local storage. The private key is hidden until you ask to see it, and is removed from the page when you clear the result or close it. (A browser can't guarantee that every copy in memory is erased, so close the tab when you're done.)
- **Hard to lose by accident.** The address can't be copied until you've saved the private key (backup, copy, or ticking "I've stored it"), and clearing or finding another asks first.
- **On diginode.tools** the tool runs inside a sandboxed frame with its own security headers, so nothing else on the website (such as analytics) can read it. The website serves the exact released file, checked against its SHA-256.

The website is fine for everyday use. **If you're wary, or the address will hold a lot of DGB, this is the safest way:**

1. Download `digibyte-vanity-address.html` from the [latest release](https://github.com/DigiNode-Tools/digibyte-vanity-address/releases/latest) and check it (below).
2. Turn off Wi-Fi and unplug any network cable.
3. Open the file in a **private or incognito window**: browser extensions are switched off there, so none can read the page.
4. Make your address. **Write the private key down or print it**, rather than copying it (clipboards can sync to other devices) or saving the backup in a synced folder.
5. **Close the browser window before you reconnect.**

For large amounts, use a computer you trust and keep up to date: no tool can protect a key from malware already on it.

## Check the release yourself

Every release is built by GitHub Actions from the tagged source, with a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations):

```sh
shasum -a 256 digibyte-vanity-address.html                  # compare with SHA256SUMS
gh attestation verify digibyte-vanity-address.html --repo DigiNode-Tools/digibyte-vanity-address
```

Or build it yourself and compare the SHA-256 (needs Node.js and Rust; the Rust version is pinned in `rust-toolchain.toml`):

```sh
npm ci
npm test
npm run build     # writes dist/digibyte-vanity-address.html and dist/SHA256SUMS
```

## How the search works

Each thread picks a random private key *k* and its public key *P = k·G*. It then checks *k+1, k+2, …* by adding *G* to the public key each step, which is far cheaper than computing every public key from scratch, and converts batches of 256 points at once (sharing one field inversion). For SegWit it compares the address characters straight from the 20-byte key hash. For Taproot it also applies the BIP86 tweak, which needs a full key multiplication per try, so it is about 40–50 times slower.

## Licence

[PolyForm Perimeter 1.0.0](LICENCE.md), like the rest of DigiNode Tools: free to use, read and check, but not to build a competing product from. Third-party libraries keep their own licences (listed in LICENCE.md).
