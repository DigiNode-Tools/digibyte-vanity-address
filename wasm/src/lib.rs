//! Vanity address search loop, compiled to WebAssembly.
//!
//! The web page gives this module a random start key `k`. It then checks the
//! keys k, k+1, k+2, ... in order, by adding the generator point G to the
//! public key each step (much cheaper than computing every public key from
//! scratch). It reports only the *offset* of a match; the page rebuilds the
//! key (k + offset) itself with a separate library and checks the address
//! again before showing anything.
//!
//! No randomness, network, clock or storage is used here: the module only
//! does arithmetic on the numbers it is given.
//!
//! Address kinds:
//!   0 = native SegWit v0, P2WPKH   (dgb1q...)  program = HASH160(compressed pubkey)
//!   1 = Taproot, BIP86 key path    (dgb1p...)  program = x(P + H_TapTweak(x(P))·G)

use k256::elliptic_curve::BatchNormalize;
use k256::elliptic_curve::CurveAffine;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Keys checked per batch. Points in a batch are converted to affine
/// coordinates together, sharing one field inversion.
pub const BATCH: usize = 256;

pub const KIND_P2WPKH: u32 = 0;
pub const KIND_P2TR: u32 = 1;
pub const MODE_PREFIX: u32 = 0;
pub const MODE_SUFFIX: u32 = 1;

const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const MAX_PATTERN: usize = 64;
const MAX_HRP: usize = 16;

/// Shared buffer for passing bytes between JavaScript and this module.
static mut IO: [u8; 256] = [0u8; 256];

pub struct Search {
    kind: u32,
    mode: u32,
    pattern: [u8; MAX_PATTERN],
    plen: usize,
    hrp: [u8; MAX_HRP],
    hlen: usize,
    /// Public key of the next key to check.
    next: ProjectivePoint,
    /// How many keys have been checked so far.
    checked: u64,
    tap_tag: Sha256,
}

static mut STATE: Option<Search> = None;

#[allow(static_mut_refs)]
fn io() -> &'static mut [u8; 256] {
    unsafe { &mut IO }
}

#[allow(static_mut_refs)]
fn state() -> Option<&'static mut Search> {
    unsafe { STATE.as_mut() }
}

/// Address of the 256-byte I/O buffer.
#[unsafe(no_mangle)]
#[allow(static_mut_refs)]
pub extern "C" fn io_ptr() -> *mut u8 {
    unsafe { IO.as_mut_ptr() }
}

/// Start a search.
///
/// I/O buffer on entry: [0..32] start key (big-endian), [32..32+plen] pattern
/// as 5-bit values (0-31), [128..128+hlen] the bech32 prefix (e.g. "dgb").
/// Returns 0 on success, or a negative error code.
#[unsafe(no_mangle)]
pub extern "C" fn init(kind: u32, mode: u32, plen: u32, hlen: u32) -> i32 {
    let buf = io();
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[0..32]);
    let mut pattern = [0u8; MAX_PATTERN];
    let plen = plen as usize;
    let hlen = hlen as usize;
    if kind > KIND_P2TR || mode > MODE_SUFFIX {
        return -1;
    }
    if plen == 0 || plen > MAX_PATTERN || hlen == 0 || hlen > MAX_HRP {
        return -2;
    }
    pattern[..plen].copy_from_slice(&buf[32..32 + plen]);
    if pattern[..plen].iter().any(|&v| v > 31) {
        return -3;
    }
    let mut hrp = [0u8; MAX_HRP];
    hrp[..hlen].copy_from_slice(&buf[128..128 + hlen]);
    match Search::new(kind, mode, &pattern[..plen], &hrp[..hlen], &key) {
        Some(s) => {
            unsafe { STATE = Some(s) };
            0
        }
        None => -4,
    }
}

/// Check up to `batches` x BATCH keys. Returns 1 if a match was found (its
/// offset from the start key is written to the I/O buffer as 8 bytes,
/// little-endian), 0 if not, or -1 if no search was started.
#[unsafe(no_mangle)]
pub extern "C" fn run(batches: u32) -> i32 {
    let Some(s) = state() else { return -1 };
    for _ in 0..batches {
        if let Some(offset) = s.batch() {
            io()[0..8].copy_from_slice(&offset.to_le_bytes());
            return 1;
        }
    }
    0
}

/// Number of keys checked so far (low and high 32 bits).
#[unsafe(no_mangle)]
pub extern "C" fn checked_lo() -> u32 {
    state().map_or(0, |s| s.checked as u32)
}
#[unsafe(no_mangle)]
pub extern "C" fn checked_hi() -> u32 {
    state().map_or(0, |s| (s.checked >> 32) as u32)
}

/// For tests: the witness program for the key in IO[0..32].
/// Writes the program to IO[0..] and returns its length (20 or 32),
/// or -1 if the key is invalid.
#[unsafe(no_mangle)]
pub extern "C" fn program_for_key(kind: u32) -> i32 {
    let buf = io();
    let mut key = [0u8; 32];
    key.copy_from_slice(&buf[0..32]);
    let Some(k) = scalar_from_bytes(&key) else { return -1 };
    let p = ProjectivePoint::mul_by_generator(&k).to_affine();
    let tag = tap_tag();
    match kind {
        KIND_P2WPKH => {
            let h = hash160_of(&p);
            buf[0..20].copy_from_slice(&h);
            20
        }
        KIND_P2TR => match taproot_output(&p, &tag) {
            Some(q) => {
                let x = q.to_affine().x();
                buf[0..32].copy_from_slice(&x);
                32
            }
            None => -1,
        },
        _ => -1,
    }
}

fn scalar_from_bytes(b: &[u8; 32]) -> Option<Scalar> {
    let fb: FieldBytes = (*b).into();
    let s: Option<Scalar> = Scalar::from_repr(fb).into();
    s.filter(|s| !bool::from(s.is_zero()))
}

fn tap_tag() -> Sha256 {
    let t = Sha256::digest(b"TapTweak");
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h
}

fn hash160_of(p: &AffinePoint) -> [u8; 20] {
    let mut c = [0u8; 33];
    c[0] = if bool::from(p.y_is_odd()) { 3 } else { 2 };
    c[1..].copy_from_slice(&p.x());
    let sha = Sha256::digest(c);
    let r = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&r);
    out
}

/// BIP86 output key: Q = lift_x(x(P)) + H_TapTweak(x(P))·G.
fn taproot_output(p: &AffinePoint, tag: &Sha256) -> Option<ProjectivePoint> {
    let x = p.x();
    let mut h = tag.clone();
    h.update(x);
    let t_bytes: [u8; 32] = h.finalize().into();
    let fb: FieldBytes = t_bytes.into();
    let t: Option<Scalar> = Scalar::from_repr(fb).into();
    let t = t?;
    let even = if bool::from(p.y_is_odd()) { -ProjectivePoint::from(*p) } else { ProjectivePoint::from(*p) };
    Some(even + ProjectivePoint::mul_by_generator(&t))
}

/// The 5-bit group number `i` of `bytes` (big-endian bit order, zero padded).
#[inline]
fn group5(bytes: &[u8], i: usize) -> u8 {
    let bit = i * 5;
    let byte = bit / 8;
    let shift = bit % 8;
    let hi = bytes[byte] as u16;
    let lo = if byte + 1 < bytes.len() { bytes[byte + 1] as u16 } else { 0 };
    (((hi << 8 | lo) >> (11 - shift)) & 31) as u8
}

fn polymod_step(chk: u32, v: u8) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let b = chk >> 25;
    let mut c = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
    for (i, g) in GEN.iter().enumerate() {
        if (b >> i) & 1 == 1 {
            c ^= g;
        }
    }
    c
}

impl Search {
    pub fn new(kind: u32, mode: u32, pattern: &[u8], hrp: &[u8], key: &[u8; 32]) -> Option<Self> {
        let k = scalar_from_bytes(key)?;
        let groups = if kind == KIND_P2WPKH { 32 } else { 52 };
        if pattern.len() > groups {
            return None;
        }
        let mut p = [0u8; MAX_PATTERN];
        p[..pattern.len()].copy_from_slice(pattern);
        let mut h = [0u8; MAX_HRP];
        h[..hrp.len()].copy_from_slice(hrp);
        Some(Search {
            kind,
            mode,
            pattern: p,
            plen: pattern.len(),
            hrp: h,
            hlen: hrp.len(),
            next: ProjectivePoint::mul_by_generator(&k),
            checked: 0,
            tap_tag: tap_tag(),
        })
    }

    pub fn checked(&self) -> u64 {
        self.checked
    }

    /// Check the next BATCH keys. Returns the offset of the first match.
    pub fn batch(&mut self) -> Option<u64> {
        let g = AffinePoint::GENERATOR;
        let mut pts = [ProjectivePoint::IDENTITY; BATCH];
        let mut cur = self.next;
        for p in pts.iter_mut() {
            *p = cur;
            cur += g;
        }
        self.next = cur;
        let affine: [AffinePoint; BATCH] = ProjectivePoint::batch_normalize(&pts);
        let base = self.checked;
        self.checked += BATCH as u64;

        match self.kind {
            KIND_P2WPKH => {
                for (i, a) in affine.iter().enumerate() {
                    let h = hash160_of(a);
                    if self.matches(&h) {
                        return Some(base + i as u64);
                    }
                }
                None
            }
            _ => {
                let mut outs = [ProjectivePoint::IDENTITY; BATCH];
                for (o, a) in outs.iter_mut().zip(affine.iter()) {
                    // A tweak >= n is astronomically unlikely; the identity
                    // point never matches a pattern, so it is simply skipped.
                    *o = taproot_output(a, &self.tap_tag).unwrap_or(ProjectivePoint::IDENTITY);
                }
                let qs: [AffinePoint; BATCH] = ProjectivePoint::batch_normalize(&outs);
                for (i, q) in qs.iter().enumerate() {
                    if bool::from(q.is_identity()) {
                        continue;
                    }
                    let x = q.x();
                    if self.matches(&x) {
                        return Some(base + i as u64);
                    }
                }
                None
            }
        }
    }

    /// Does this witness program give an address matching the pattern?
    fn matches(&self, program: &[u8]) -> bool {
        let groups = (program.len() * 8).div_ceil(5);
        let pat = &self.pattern[..self.plen];
        if self.mode == MODE_PREFIX {
            return pat.iter().enumerate().all(|(i, &v)| group5(program, i) == v);
        }
        // Suffix: the address ends with the program's groups then a
        // 6-character checksum, so build the checksum and compare the tail.
        let mut data = [0u8; 1 + 52 + 6];
        data[0] = self.kind as u8; // witness version
        for i in 0..groups {
            data[1 + i] = group5(program, i);
        }
        let n = 1 + groups;
        let mut chk: u32 = 1;
        for &c in &self.hrp[..self.hlen] {
            chk = polymod_step(chk, c >> 5);
        }
        chk = polymod_step(chk, 0);
        for &c in &self.hrp[..self.hlen] {
            chk = polymod_step(chk, c & 31);
        }
        for &v in &data[..n] {
            chk = polymod_step(chk, v);
        }
        for _ in 0..6 {
            chk = polymod_step(chk, 0);
        }
        chk ^= if self.kind == KIND_P2WPKH { BECH32_CONST } else { BECH32M_CONST };
        for i in 0..6 {
            data[n + i] = ((chk >> (5 * (5 - i))) & 31) as u8;
        }
        // Characters after "hrp1" + version character: data[1..n+6].
        let tail = &data[1..n + 6];
        if pat.len() > tail.len() {
            return false;
        }
        &tail[tail.len() - pat.len()..] == pat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn encode(hrp: &str, version: u8, program: &[u8]) -> String {
        let groups = (program.len() * 8).div_ceil(5);
        let mut data = vec![version];
        for i in 0..groups {
            data.push(group5(program, i));
        }
        let mut chk: u32 = 1;
        for c in hrp.bytes() {
            chk = polymod_step(chk, c >> 5);
        }
        chk = polymod_step(chk, 0);
        for c in hrp.bytes() {
            chk = polymod_step(chk, c & 31);
        }
        for &v in &data {
            chk = polymod_step(chk, v);
        }
        for _ in 0..6 {
            chk = polymod_step(chk, 0);
        }
        chk ^= if version == 0 { BECH32_CONST } else { BECH32M_CONST };
        for i in 0..6 {
            data.push(((chk >> (5 * (5 - i))) & 31) as u8);
        }
        let mut s = format!("{hrp}1");
        for v in data {
            s.push(CHARSET[v as usize] as char);
        }
        s
    }

    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = n;
        k
    }

    fn address(kind: u32, hrp: &str, k: &[u8; 32]) -> String {
        let s = scalar_from_bytes(k).unwrap();
        let p = ProjectivePoint::mul_by_generator(&s).to_affine();
        if kind == KIND_P2WPKH {
            encode(hrp, 0, &hash160_of(&p))
        } else {
            let q = taproot_output(&p, &tap_tag()).unwrap().to_affine();
            encode(hrp, 1, &q.x())
        }
    }

    #[test]
    fn bitcoin_vectors() {
        // Private key 1: well-known Bitcoin addresses.
        assert_eq!(address(KIND_P2WPKH, "bc", &key(1)), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        // BIP86 test vector m/86'/0'/0'/0/0: internal key -> output key -> address.
        use k256::elliptic_curve::group::GroupEncoding;
        let mut c = [0u8; 33];
        c[0] = 2;
        c[1..].copy_from_slice(&hex32("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"));
        let p: Option<AffinePoint> = AffinePoint::from_bytes(&c.into()).into();
        let q = taproot_output(&p.unwrap(), &tap_tag()).unwrap().to_affine();
        assert_eq!(
            encode("bc", 1, &q.x()),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// The incremental search must visit exactly start, start+1, start+2, ...
    #[test]
    fn search_walks_consecutive_keys() {
        for kind in [KIND_P2WPKH, KIND_P2TR] {
            let start = hex32("7f0c3a1e5b9d2c4f6a8e0b1d3c5f7a9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f13");
            let hrp = "dgb";
            for offset in [0u64, 1, 2, 255, 256, 257, 700] {
                // Key start + offset.
                let mut k = start;
                let mut carry = offset as u128;
                for b in k.iter_mut().rev() {
                    let v = *b as u128 + (carry & 0xff);
                    *b = v as u8;
                    carry = (carry >> 8) + (v >> 8);
                }
                let addr = address(kind, hrp, &k);
                let tail = &addr[hrp.len() + 2..]; // after "dgb1q" / "dgb1p"
                // 10 characters: a chance match on another key is ~1 in 10^15.
                let pat: Vec<u8> = tail[..10]
                    .bytes()
                    .map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8)
                    .collect();
                let mut s = Search::new(kind, MODE_PREFIX, &pat, hrp.as_bytes(), &start).unwrap();
                let mut found = None;
                while s.checked() <= offset {
                    if let Some(o) = s.batch() {
                        found = Some(o);
                        break;
                    }
                }
                assert_eq!(found, Some(offset), "kind {kind}");
            }
        }
    }

    #[test]
    fn suffix_matches_checksum() {
        let k = key(7);
        for kind in [KIND_P2WPKH, KIND_P2TR] {
            let addr = address(kind, "dgb", &k);
            let last: Vec<u8> = addr[addr.len() - 3..]
                .bytes()
                .map(|c| CHARSET.iter().position(|&x| x == c).unwrap() as u8)
                .collect();
            let s = Search::new(kind, MODE_SUFFIX, &last, b"dgb", &k).unwrap();
            let sc = scalar_from_bytes(&k).unwrap();
            let p = ProjectivePoint::mul_by_generator(&sc).to_affine();
            let prog: Vec<u8> = if kind == KIND_P2WPKH {
                hash160_of(&p).to_vec()
            } else {
                taproot_output(&p, &tap_tag()).unwrap().to_affine().x().to_vec()
            };
            assert!(s.matches(&prog), "{addr}");
        }
    }
}
