//! Vector classification of line bytes into candidate positions.
//!
//! The scanner's exact context gates decide, per byte, which finders may
//! start a match there from the previous and next bytes. Evaluating those
//! tables costs a few dependent loads per byte. This module computes a
//! superset of the gated candidates sixteen bytes at a time with SIMD, so
//! the exact tables only run on the (few) positions that survive.
//!
//! Every byte gets a *category* (digit, hex letter, other letter, `.`, `:`,
//! high byte, other). Each category carries two coarse rules: the
//! categories forbidden for the previous byte and for the next byte (see
//! [`Rules`]). Category and start-byte membership are nibble lookups
//! (`tbl`/`pshufb`), which represent a set as the product of a low-nibble
//! set and a high-nibble set; the categories and the ASCII start sets are
//! exact products, and the only widening (high start bytes) adds
//! candidates, never removes one.

/// Category bits. Letters are split so that `g-o`/`G-O` and `p-z`/`P-Z`
/// are exact nibble products; together they form [`CAT_OTHER_ALPHA`].
pub(crate) const CAT_DIGIT: u8 = 1 << 0;
pub(crate) const CAT_HEX_ALPHA: u8 = 1 << 1;
pub(crate) const CAT_ALPHA_GO: u8 = 1 << 2;
pub(crate) const CAT_ALPHA_PZ: u8 = 1 << 3;
pub(crate) const CAT_DOT: u8 = 1 << 4;
pub(crate) const CAT_COLON: u8 = 1 << 5;
pub(crate) const CAT_HIGH: u8 = 1 << 6;
/// Everything else; computed as "no other category" in the vector path.
pub(crate) const CAT_OTHER: u8 = 1 << 7;
pub(crate) const CAT_OTHER_ALPHA: u8 = CAT_ALPHA_GO | CAT_ALPHA_PZ;
pub(crate) const CAT_ALL: u8 = 0xFF;
/// Category value for "no byte" (start or end of the line): nothing is
/// forbidden there.
pub(crate) const CAT_NONE: u8 = 0;

/// Bytes per block.
pub(crate) const BLOCK: usize = 16;

pub(crate) const fn category(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => CAT_DIGIT,
        b'a'..=b'f' | b'A'..=b'F' => CAT_HEX_ALPHA,
        b'g'..=b'o' | b'G'..=b'O' => CAT_ALPHA_GO,
        b'p'..=b'z' | b'P'..=b'Z' => CAT_ALPHA_PZ,
        b'.' => CAT_DOT,
        b':' => CAT_COLON,
        0x80..=0xFF => CAT_HIGH,
        _ => CAT_OTHER,
    }
}

const fn build_category_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = category(i as u8);
        i += 1;
    }
    table
}

pub(crate) static CATEGORY: [u8; 256] = build_category_table();

/// Up to eight byte sets encoded as nibble lookup tables. Byte `b` is in
/// set `bit` when `lo[b & 15] & hi[b >> 4] & bit != 0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NibbleSets {
    pub(crate) lo: [u8; 16],
    pub(crate) hi: [u8; 16],
}

impl NibbleSets {
    pub(crate) const EMPTY: NibbleSets = NibbleSets {
        lo: [0; 16],
        hi: [0; 16],
    };

    pub(crate) const fn insert(&mut self, bit: u8, byte: u8) {
        self.lo[(byte & 0x0F) as usize] |= bit;
        self.hi[(byte >> 4) as usize] |= bit;
    }

    /// Bits of every set whose product closure contains `byte`.
    #[cfg(test)]
    pub(crate) const fn lookup(&self, byte: u8) -> u8 {
        self.lo[(byte & 0x0F) as usize] & self.hi[(byte >> 4) as usize]
    }
}

const fn build_category_sets() -> NibbleSets {
    let mut sets = NibbleSets::EMPTY;
    let mut i = 0;
    while i < 256 {
        let cat = category(i as u8);
        if cat != CAT_OTHER {
            sets.insert(cat, i as u8);
        }
        i += 1;
    }
    sets
}

/// Category sets. Every category except [`CAT_OTHER`] is an exact product,
/// so this lookup is exact; `CAT_OTHER` is derived as the empty result.
pub(crate) static CATEGORY_SETS: NibbleSets = build_category_sets();

/// The coarse rules of a scanner: which bytes can start a match and, per
/// byte category, two alternative rules on the surrounding bytes.
///
/// Start-byte membership is exact for ASCII: every high-nibble row owns a
/// bit, so the nibble product never crosses rows. Rows `8-B` and `C-F`
/// share a bit each, so high start bytes are widened within those rows.
///
/// Rules are attached to categories because the category is what the
/// vector path can index with. Each category keeps two alternatives so a
/// finder with no previous-byte constraint (keycap emoji on digits) does not
/// erase the constraints of the others: `a` unions the finders that
/// constrain the previous byte, `b` unions those that do not. A lane is a
/// candidate when either alternative accepts its neighbours.
#[derive(Clone, Debug)]
pub(crate) struct Rules {
    pub(crate) start: NibbleSets,
    /// Forbidden previous/next categories per alternative, indexed by
    /// category index (0..8); entries `8..16` are unused.
    pub(crate) prev_forbidden_a: [u8; 16],
    pub(crate) next_forbidden_a: [u8; 16],
    pub(crate) prev_forbidden_b: [u8; 16],
    pub(crate) next_forbidden_b: [u8; 16],
    /// Exact start membership, for the scalar path and for tests.
    pub(crate) is_start: [bool; 256],
}

/// Index of a one-hot category byte.
pub(crate) const fn category_index(cat: u8) -> usize {
    cat.trailing_zeros() as usize
}

/// Row bit used by the start-byte nibble sets.
const fn row_bit(byte: u8) -> u8 {
    match byte >> 4 {
        row @ 0..=7 => 1 << row,
        0x8..=0xB => 1 << 6,
        _ => 1 << 7,
    }
}

impl Rules {
    /// Builds the rules from `(byte, prev_allowed, next_allowed)` items, one
    /// per finder and start byte: the categories allowed immediately before
    /// and after a match starting at `byte` (0 means "no rule", widened to
    /// all).
    pub(crate) fn build(items: impl IntoIterator<Item = (u8, u8, u8)>) -> Rules {
        let widen = |cats: u8| if cats == 0 { CAT_ALL } else { cats };
        let mut prev_a = [0u8; 16];
        let mut next_a = [0u8; 16];
        let mut prev_b = [0u8; 16];
        let mut next_b = [0u8; 16];
        let mut rules = Rules {
            start: NibbleSets::EMPTY,
            prev_forbidden_a: [0xFF; 16],
            next_forbidden_a: [0xFF; 16],
            prev_forbidden_b: [0xFF; 16],
            next_forbidden_b: [0xFF; 16],
            is_start: [false; 256],
        };
        for (byte, prev, next) in items {
            let (prev, next) = (widen(prev), widen(next));
            rules.is_start[byte as usize] = true;
            rules.start.insert(row_bit(byte), byte);
            let c = category_index(CATEGORY[byte as usize]);
            if prev == CAT_ALL {
                prev_b[c] |= prev;
                next_b[c] |= next;
            } else {
                prev_a[c] |= prev;
                next_a[c] |= next;
            }
        }
        for c in 0..8 {
            rules.prev_forbidden_a[c] = !prev_a[c];
            rules.next_forbidden_a[c] = !next_a[c];
            rules.prev_forbidden_b[c] = !prev_b[c];
            rules.next_forbidden_b[c] = !next_b[c];
        }
        rules
    }

    /// Whether a lane with category `cat` between `prev` and `next` passes.
    #[inline]
    pub(crate) fn accepts(&self, cat: u8, prev: u8, next: u8) -> bool {
        let c = category_index(cat);
        (prev & self.prev_forbidden_a[c] == 0 && next & self.next_forbidden_a[c] == 0)
            || (prev & self.prev_forbidden_b[c] == 0 && next & self.next_forbidden_b[c] == 0)
    }

    /// Reference implementation of one block with exact start membership.
    /// Returns one bit per byte.
    pub(crate) fn candidates_scalar(&self, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64 {
        let mut mask = 0u64;
        for (lane, &b) in block.iter().enumerate() {
            if !self.is_start[b as usize] {
                continue;
            }
            let prev = if lane == 0 {
                prev_cat
            } else {
                CATEGORY[block[lane - 1] as usize]
            };
            let next = if lane + 1 == BLOCK {
                next_cat
            } else {
                CATEGORY[block[lane + 1] as usize]
            };
            if self.accepts(CATEGORY[b as usize], prev, next) {
                mask |= 1 << lane;
            }
        }
        mask
    }
}

/// A block classifier: returns the candidate lanes of a 16-byte block as a
/// bitmask with [`Backend::STRIDE`] bits per lane (all bits of a lane set
/// when it is a candidate). `prev_cat`/`next_cat` are the categories of the
/// bytes around the block, or [`CAT_NONE`] at the start/end of the line.
pub(crate) trait Backend: Copy {
    const NAME: &'static str;
    const STRIDE: u32;

    fn block(rules: &Rules, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64;

    /// Lane index of the lowest candidate bit.
    #[inline(always)]
    fn lane(mask: u64) -> usize {
        (mask.trailing_zeros() / Self::STRIDE) as usize
    }

    /// Clears all bits of `lane`.
    #[inline(always)]
    fn clear(mask: u64, lane: usize) -> u64 {
        let lane_bits = (1u64 << Self::STRIDE) - 1;
        mask & !(lane_bits << (lane as u32 * Self::STRIDE))
    }

    /// Mask of the first `n` lanes.
    #[inline(always)]
    fn lanes(n: usize) -> u64 {
        let bits = n as u32 * Self::STRIDE;
        if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }
}

/// Portable table-driven backend (one bit per lane).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scalar;

impl Backend for Scalar {
    const NAME: &'static str = "scalar";
    const STRIDE: u32 = 1;

    #[inline]
    fn block(rules: &Rules, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64 {
        rules.candidates_scalar(block, prev_cat, next_cat)
    }
}

/// Which backend [`detect`] selected; the scanner dispatches on it so the
/// block function inlines into the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Scalar,
    #[cfg(target_arch = "aarch64")]
    Neon,
    #[cfg(target_arch = "x86_64")]
    Ssse3,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Scalar => Scalar::NAME,
            #[cfg(target_arch = "aarch64")]
            Kind::Neon => neon::Neon::NAME,
            #[cfg(target_arch = "x86_64")]
            Kind::Ssse3 => ssse3::Ssse3::NAME,
        }
    }
}

/// The fastest backend available on this machine.
pub(crate) fn detect() -> Kind {
    #[cfg(target_arch = "aarch64")]
    {
        return Kind::Neon;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("ssse3") {
            return Kind::Ssse3;
        }
    }
    #[allow(unreachable_code)]
    Kind::Scalar
}

#[cfg(target_arch = "aarch64")]
pub(crate) mod neon {
    use super::{BLOCK, Backend, CAT_OTHER, CATEGORY_SETS, Rules};
    use core::arch::aarch64::*;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Neon;

    impl Backend for Neon {
        const NAME: &'static str = "neon";
        const STRIDE: u32 = 4;

        #[inline(always)]
        fn block(rules: &Rules, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64 {
            // SAFETY: NEON is part of the aarch64 baseline; every load reads
            // exactly 16 bytes from a `[u8; 16]`.
            unsafe {
                let v = vld1q_u8(block.as_ptr());
                let lo = vandq_u8(v, vdupq_n_u8(0x0F));
                let hi = vshrq_n_u8::<4>(v);

                let cat_lo = vqtbl1q_u8(vld1q_u8(CATEGORY_SETS.lo.as_ptr()), lo);
                let cat_hi = vqtbl1q_u8(vld1q_u8(CATEGORY_SETS.hi.as_ptr()), hi);
                let cat = vandq_u8(cat_lo, cat_hi);
                let other = vandq_u8(vceqzq_u8(cat), vdupq_n_u8(CAT_OTHER));
                let cat = vorrq_u8(cat, other);
                // Category index: popcount(cat - 1) for a one-hot byte.
                let index = vcntq_u8(vsubq_u8(cat, vdupq_n_u8(1)));

                let start_lo = vqtbl1q_u8(vld1q_u8(rules.start.lo.as_ptr()), lo);
                let start_hi = vqtbl1q_u8(vld1q_u8(rules.start.hi.as_ptr()), hi);
                let is_start = vtstq_u8(start_lo, start_hi);

                let prev = vextq_u8::<15>(vdupq_n_u8(prev_cat), cat);
                let next = vextq_u8::<1>(cat, vdupq_n_u8(next_cat));
                let bad_a = vorrq_u8(
                    vtstq_u8(
                        prev,
                        vqtbl1q_u8(vld1q_u8(rules.prev_forbidden_a.as_ptr()), index),
                    ),
                    vtstq_u8(
                        next,
                        vqtbl1q_u8(vld1q_u8(rules.next_forbidden_a.as_ptr()), index),
                    ),
                );
                let bad_b = vorrq_u8(
                    vtstq_u8(
                        prev,
                        vqtbl1q_u8(vld1q_u8(rules.prev_forbidden_b.as_ptr()), index),
                    ),
                    vtstq_u8(
                        next,
                        vqtbl1q_u8(vld1q_u8(rules.next_forbidden_b.as_ptr()), index),
                    ),
                );
                let cand = vbicq_u8(is_start, vandq_u8(bad_a, bad_b));

                // Narrowing shift: each 0x00/0xFF lane becomes a nibble.
                let nibbles = vshrn_n_u16::<4>(vreinterpretq_u16_u8(cand));
                vget_lane_u64::<0>(vreinterpret_u64_u8(nibbles))
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod ssse3 {
    use super::{BLOCK, Backend, CAT_OTHER, CATEGORY_SETS, Rules};
    use core::arch::x86_64::*;

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Ssse3;

    impl Backend for Ssse3 {
        const NAME: &'static str = "ssse3";
        const STRIDE: u32 = 1;

        #[inline(always)]
        fn block(rules: &Rules, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64 {
            // SAFETY: only reached from a `#[target_feature(enable =
            // "ssse3")]` walk that `detect` selected after checking the CPU.
            unsafe { candidates(rules, block, prev_cat, next_cat) }
        }
    }

    #[target_feature(enable = "ssse3")]
    #[inline]
    unsafe fn candidates(rules: &Rules, block: &[u8; BLOCK], prev_cat: u8, next_cat: u8) -> u64 {
        // SAFETY: every load reads exactly 16 bytes from a `[u8; 16]`.
        unsafe {
            let load = |p: *const u8| _mm_loadu_si128(p as *const __m128i);
            let v = load(block.as_ptr());
            let low_nibbles = _mm_set1_epi8(0x0F);
            let lo = _mm_and_si128(v, low_nibbles);
            let hi = _mm_and_si128(_mm_srli_epi16::<4>(v), low_nibbles);
            let zero = _mm_setzero_si128();
            let ones = _mm_set1_epi8(-1);
            let tst = |x: __m128i, m: __m128i| {
                _mm_andnot_si128(_mm_cmpeq_epi8(_mm_and_si128(x, m), zero), ones)
            };

            let cat_lo = _mm_shuffle_epi8(load(CATEGORY_SETS.lo.as_ptr()), lo);
            let cat_hi = _mm_shuffle_epi8(load(CATEGORY_SETS.hi.as_ptr()), hi);
            let cat = _mm_and_si128(cat_lo, cat_hi);
            let other = _mm_and_si128(_mm_cmpeq_epi8(cat, zero), _mm_set1_epi8(CAT_OTHER as i8));
            let cat = _mm_or_si128(cat, other);
            // Category index: popcount(cat - 1) via a nibble popcount table.
            let minus_one = _mm_sub_epi8(cat, _mm_set1_epi8(1));
            let popcnt_table = _mm_setr_epi8(0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4);
            let pop_lo = _mm_shuffle_epi8(popcnt_table, _mm_and_si128(minus_one, low_nibbles));
            let pop_hi = _mm_shuffle_epi8(
                popcnt_table,
                _mm_and_si128(_mm_srli_epi16::<4>(minus_one), low_nibbles),
            );
            let index = _mm_add_epi8(pop_lo, pop_hi);

            let start_lo = _mm_shuffle_epi8(load(rules.start.lo.as_ptr()), lo);
            let start_hi = _mm_shuffle_epi8(load(rules.start.hi.as_ptr()), hi);
            let is_start = tst(start_lo, start_hi);

            let prev = _mm_alignr_epi8::<15>(cat, _mm_set1_epi8(prev_cat as i8));
            let next = _mm_alignr_epi8::<1>(_mm_set1_epi8(next_cat as i8), cat);
            let bad_a = _mm_or_si128(
                tst(
                    prev,
                    _mm_shuffle_epi8(load(rules.prev_forbidden_a.as_ptr()), index),
                ),
                tst(
                    next,
                    _mm_shuffle_epi8(load(rules.next_forbidden_a.as_ptr()), index),
                ),
            );
            let bad_b = _mm_or_si128(
                tst(
                    prev,
                    _mm_shuffle_epi8(load(rules.prev_forbidden_b.as_ptr()), index),
                ),
                tst(
                    next,
                    _mm_shuffle_epi8(load(rules.next_forbidden_b.as_ptr()), index),
                ),
            );
            let cand = _mm_andnot_si128(_mm_and_si128(bad_a, bad_b), is_start);
            _mm_movemask_epi8(cand) as u32 as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_partition_every_byte() {
        for b in 0..=255u8 {
            let cat = CATEGORY[b as usize];
            assert_eq!(cat.count_ones(), 1, "byte {b:#x} has category {cat:#b}");
            let via_sets = match CATEGORY_SETS.lookup(b) {
                0 => CAT_OTHER,
                bits => bits,
            };
            assert_eq!(via_sets, cat, "nibble sets disagree on byte {b:#x}");
        }
    }

    fn sample_rules() -> Rules {
        // Hex digits: after a non-hex byte, before a hex digit (finder 1),
        // or digits anywhere before a high byte (finder 2, keycap-like).
        // `$` anywhere before a letter; `.` after "other" before `/`.
        let mut items = Vec::new();
        for b in 0..=255u8 {
            if b.is_ascii_hexdigit() {
                items.push((
                    b,
                    CAT_ALL & !(CAT_DIGIT | CAT_HEX_ALPHA),
                    CAT_DIGIT | CAT_HEX_ALPHA,
                ));
            }
            if b.is_ascii_digit() {
                items.push((b, CAT_ALL, CAT_HIGH));
            }
        }
        items.push((b'$', CAT_ALL, CAT_OTHER_ALPHA | CAT_HEX_ALPHA));
        items.push((b'.', CAT_OTHER, CAT_OTHER));
        Rules::build(items)
    }

    #[test]
    fn start_membership_is_exact_for_ascii() {
        let rules = sample_rules();
        for b in 0..=255u8 {
            let expected = b.is_ascii_hexdigit() || b == b'$' || b == b'.';
            assert_eq!(rules.is_start[b as usize], expected, "byte {b:#x}");
            assert_eq!(
                rules.start.lookup(b) != 0,
                expected,
                "nibble sets on byte {b:#x}"
            );
        }
        // High start bytes are widened within their row group only.
        let rules = Rules::build([(0xE2, CAT_ALL, CAT_HIGH), (0xF0, CAT_ALL, CAT_HIGH)]);
        assert_ne!(rules.start.lookup(0xE0), 0);
        assert_eq!(rules.start.lookup(0x32), 0);
        assert_eq!(rules.start.lookup(0xA2), 0);
    }

    #[test]
    fn alternatives_keep_constrained_finders_precise() {
        let rules = sample_rules();
        // A digit inside a digit run is only a candidate before a high byte.
        assert!(!rules.accepts(CAT_DIGIT, CAT_DIGIT, CAT_DIGIT));
        assert!(rules.accepts(CAT_DIGIT, CAT_DIGIT, CAT_HIGH));
        assert!(rules.accepts(CAT_DIGIT, CAT_OTHER, CAT_DIGIT));
        // Hex letters have no unconstrained finder.
        assert!(!rules.accepts(CAT_HEX_ALPHA, CAT_HEX_ALPHA, CAT_HIGH));
        assert!(rules.accepts(CAT_HEX_ALPHA, CAT_OTHER_ALPHA, CAT_DIGIT));
        // Line edges (CAT_NONE) never forbid.
        assert!(rules.accepts(CAT_HEX_ALPHA, CAT_NONE, CAT_NONE));
        // A category without any start byte accepts nothing.
        assert!(!rules.accepts(CAT_COLON, CAT_OTHER, CAT_OTHER));
    }

    fn lanes_of<B: Backend>(mut mask: u64) -> Vec<usize> {
        let mut lanes = Vec::new();
        while mask != 0 {
            let lane = B::lane(mask);
            lanes.push(lane);
            mask = B::clear(mask, lane);
        }
        lanes
    }

    fn check_backend<B: Backend>(rules: &Rules) {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = b"0123456789abcdefxyz$./ :@-";
        for _ in 0..3000 {
            let mut block = [0u8; BLOCK];
            for b in block.iter_mut() {
                let r = next();
                *b = if r % 5 == 0 {
                    (r >> 8) as u8
                } else {
                    alphabet[(r >> 8) as usize % alphabet.len()]
                };
            }
            let prev_cat = if next() % 3 == 0 {
                CAT_NONE
            } else {
                CATEGORY[(next() >> 8) as u8 as usize]
            };
            let next_cat = if next() % 3 == 0 {
                CAT_NONE
            } else {
                CATEGORY[(next() >> 8) as u8 as usize]
            };
            let expected = lanes_of::<Scalar>(rules.candidates_scalar(&block, prev_cat, next_cat));
            let got = lanes_of::<B>(B::block(rules, &block, prev_cat, next_cat));
            // Vector groups use the product closure, so they may only add.
            for lane in &expected {
                assert!(
                    got.contains(lane),
                    "{} lost lane {lane} on {block:?}",
                    B::NAME
                );
            }
            for lane in &got {
                assert_ne!(
                    rules.start.lookup(block[*lane]),
                    0,
                    "{} invented lane {lane} on {block:?}",
                    B::NAME
                );
            }
        }
    }

    #[test]
    fn backends_agree_with_the_scalar_reference() {
        let rules = sample_rules();
        check_backend::<Scalar>(&rules);
        #[cfg(target_arch = "aarch64")]
        check_backend::<neon::Neon>(&rules);
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("ssse3") {
            check_backend::<ssse3::Ssse3>(&rules);
        }
    }

    #[test]
    fn lane_helpers_round_trip() {
        fn check<B: Backend>() {
            assert_eq!(
                lanes_of::<B>(B::lanes(BLOCK)),
                (0..BLOCK).collect::<Vec<_>>()
            );
            assert_eq!(lanes_of::<B>(B::lanes(3)), vec![0, 1, 2]);
            assert_eq!(B::lanes(0), 0);
        }
        check::<Scalar>();
        #[cfg(target_arch = "aarch64")]
        check::<neon::Neon>();
        #[cfg(target_arch = "x86_64")]
        check::<ssse3::Ssse3>();
    }
}
