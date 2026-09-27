//! The byte search of a `memchr` pass: every position holding one of up to
//! three bytes, optionally only where the byte before it belongs to a set.
//!
//! `memchr_iter` restarts its vector loop after every hit, which dominates
//! when hits are dense (the colons of timestamps in a log). This search
//! takes a mask per 64 bytes and walks its bits, and tests the previous
//! byte of every hit in the same vectors, so a colon after a digit never
//! reaches the scanner when no finder of the pass can start there.

/// A byte set as two nibble tables (the "shufti" technique): byte `b` is a
/// member when `lo[b & 15] & hi[b >> 4] != 0`. Eight buckets distinguish up
/// to eight distinct low-nibble patterns; beyond that buckets are merged,
/// which only adds members.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NibbleSet {
    lo: [u8; 16],
    hi: [u8; 16],
}

impl NibbleSet {
    /// Every byte.
    const ALL: NibbleSet = NibbleSet {
        lo: [0xFF; 16],
        hi: [0xFF; 16],
    };

    /// A superset of `members`, or `None` when it would hold every byte.
    pub(crate) fn new(members: &[bool; 256]) -> Option<Self> {
        // Low nibbles present under each high nibble.
        let mut patterns = [0u16; 16];
        for (b, _) in members.iter().enumerate().filter(|(_, m)| **m) {
            patterns[b >> 4] |= 1 << (b & 15);
        }
        let mut buckets: Vec<u16> = Vec::new();
        for &pattern in patterns.iter().filter(|p| **p != 0) {
            if !buckets.contains(&pattern) {
                buckets.push(pattern);
            }
        }
        // Merge the pair whose union adds the fewest members until eight
        // buckets remain.
        while buckets.len() > 8 {
            let mut best = (u32::MAX, 0, 1);
            for i in 0..buckets.len() {
                for j in i + 1..buckets.len() {
                    let union = buckets[i] | buckets[j];
                    let added =
                        2 * union.count_ones() - buckets[i].count_ones() - buckets[j].count_ones();
                    if added < best.0 {
                        best = (added, i, j);
                    }
                }
            }
            let (_, i, j) = best;
            let merged = buckets[i] | buckets[j];
            buckets.swap_remove(j);
            buckets[i] = merged;
        }
        let mut set = NibbleSet {
            lo: [0; 16],
            hi: [0; 16],
        };
        for (h, &pattern) in patterns.iter().enumerate() {
            if pattern == 0 {
                continue;
            }
            // The bucket covering the pattern (merged ones cover it too).
            let bucket = buckets
                .iter()
                .position(|&b| b & pattern == pattern)
                .expect("every pattern has a bucket");
            set.hi[h] |= 1 << bucket;
        }
        for (bucket, &pattern) in buckets.iter().enumerate() {
            for lo in 0..16 {
                if pattern & (1 << lo) != 0 {
                    set.lo[lo] |= 1 << bucket;
                }
            }
        }
        (0..=255u8).any(|b| !set.contains(b)).then_some(set)
    }

    #[inline(always)]
    pub(crate) fn contains(&self, b: u8) -> bool {
        self.lo[usize::from(b & 15)] & self.hi[usize::from(b >> 4)] != 0
    }
}

/// Which implementation runs the search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Engine {
    Memchr,
    #[cfg(target_arch = "aarch64")]
    Neon,
    #[cfg(target_arch = "x86_64")]
    Ssse3,
}

/// Calls `hit` with every position of `input` holding one of `bytes` (one
/// to three) whose previous byte is in `prev`, when given; position 0 has
/// no previous byte and always qualifies. Stops when `hit` returns `true`.
#[inline(always)]
pub(crate) fn search(
    engine: Engine,
    bytes: &[u8],
    prev: Option<&NibbleSet>,
    input: &[u8],
    hit: impl FnMut(usize) -> bool,
) {
    debug_assert!((1..=3).contains(&bytes.len()));
    match engine {
        Engine::Memchr => memchr_search(bytes, prev, input, hit),
        #[cfg(target_arch = "aarch64")]
        Engine::Neon => neon::search(bytes, prev, input, hit),
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `Engine::Ssse3` is only selected after the CPU check.
        Engine::Ssse3 => unsafe { ssse3::search(bytes, prev, input, hit) },
    }
}

impl Engine {
    /// The engine matching a block classifier backend, whose detection
    /// covers the same CPU features.
    pub(crate) fn of(backend: crate::classify::Kind) -> Self {
        match backend {
            crate::classify::Kind::Scalar => Engine::Memchr,
            #[cfg(target_arch = "aarch64")]
            crate::classify::Kind::Neon => Engine::Neon,
            #[cfg(target_arch = "x86_64")]
            crate::classify::Kind::Ssse3 => Engine::Ssse3,
        }
    }
}

#[inline(always)]
fn qualifies(prev: Option<&NibbleSet>, input: &[u8], pos: usize) -> bool {
    pos == 0 || prev.is_none_or(|set| set.contains(input[pos - 1]))
}

fn memchr_search(
    bytes: &[u8],
    prev: Option<&NibbleSet>,
    input: &[u8],
    mut hit: impl FnMut(usize) -> bool,
) {
    let mut each = |pos: usize| qualifies(prev, input, pos) && hit(pos);
    match *bytes {
        [a] => {
            for pos in memchr::memchr_iter(a, input) {
                if each(pos) {
                    return;
                }
            }
        }
        [a, b] => {
            for pos in memchr::memchr2_iter(a, b, input) {
                if each(pos) {
                    return;
                }
            }
        }
        [a, b, c] => {
            for pos in memchr::memchr3_iter(a, b, c, input) {
                if each(pos) {
                    return;
                }
            }
        }
        _ => unreachable!("a search looks for one to three bytes"),
    }
}

/// The bytes past the last whole group of 64, scalar.
#[inline(always)]
fn tail(
    bytes: &[u8],
    prev: Option<&NibbleSet>,
    input: &[u8],
    from: usize,
    hit: &mut impl FnMut(usize) -> bool,
) -> bool {
    for pos in from..input.len() {
        if bytes.contains(&input[pos]) && qualifies(prev, input, pos) && hit(pos) {
            return true;
        }
    }
    false
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::{NibbleSet, tail};
    use core::arch::aarch64::*;

    /// One instantiation per caller: the byte count and the filter are
    /// runtime values (a missing byte repeats the first, a missing filter
    /// admits every byte), since the caller's probe inlines into it.
    #[inline(always)]
    pub(super) fn search(
        bytes: &[u8],
        prev: Option<&NibbleSet>,
        input: &[u8],
        mut hit: impl FnMut(usize) -> bool,
    ) {
        let hit = &mut hit;
        const WEIGHTS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
        let len = input.len();
        let ptr = input.as_ptr();
        let set = prev.unwrap_or(&NibbleSet::ALL);
        // SAFETY: baseline NEON; every load reads 16 bytes inside
        // `input[base..base + 64]`, which the loop condition guarantees.
        unsafe {
            let a = vdupq_n_u8(bytes[0]);
            let b = vdupq_n_u8(*bytes.get(1).unwrap_or(&bytes[0]));
            let c = vdupq_n_u8(*bytes.get(2).unwrap_or(&bytes[0]));
            let weights = vld1q_u8(WEIGHTS.as_ptr());
            let lo = vld1q_u8(set.lo.as_ptr());
            let hi = vld1q_u8(set.hi.as_ptr());
            let low_nibble = vdupq_n_u8(0x0F);
            let eq = |v: uint8x16_t| -> uint8x16_t {
                vorrq_u8(vorrq_u8(vceqq_u8(v, a), vceqq_u8(v, b)), vceqq_u8(v, c))
            };
            let member = |p: uint8x16_t| -> uint8x16_t {
                let l = vqtbl1q_u8(lo, vandq_u8(p, low_nibble));
                let h = vqtbl1q_u8(hi, vshrq_n_u8::<4>(p));
                vtstq_u8(l, h)
            };
            // The byte before position 0 counts as a member.
            let mut last = vdupq_n_u8(0);
            let mut first = true;
            let mut base = 0;
            while base + 64 <= len {
                let v0 = vld1q_u8(ptr.add(base));
                let v1 = vld1q_u8(ptr.add(base + 16));
                let v2 = vld1q_u8(ptr.add(base + 32));
                let v3 = vld1q_u8(ptr.add(base + 48));
                let mut e0 = eq(v0);
                let mut e1 = eq(v1);
                let mut e2 = eq(v2);
                let mut e3 = eq(v3);
                if vmaxvq_u8(vorrq_u8(vorrq_u8(e0, e1), vorrq_u8(e2, e3))) != 0 {
                    let mut m0 = member(vextq_u8::<15>(last, v0));
                    if first {
                        m0 = vsetq_lane_u8::<0>(0xFF, m0);
                    }
                    e0 = vandq_u8(e0, m0);
                    e1 = vandq_u8(e1, member(vextq_u8::<15>(v0, v1)));
                    e2 = vandq_u8(e2, member(vextq_u8::<15>(v1, v2)));
                    e3 = vandq_u8(e3, member(vextq_u8::<15>(v2, v3)));
                    // One bit per byte: weigh each lane by its bit and add
                    // neighbours pairwise until each byte holds eight lanes.
                    let s01 = vpaddq_u8(vandq_u8(e0, weights), vandq_u8(e1, weights));
                    let s23 = vpaddq_u8(vandq_u8(e2, weights), vandq_u8(e3, weights));
                    let s = vpaddq_u8(s01, s23);
                    let s = vpaddq_u8(s, s);
                    let mut mask = vgetq_lane_u64::<0>(vreinterpretq_u64_u8(s));
                    while mask != 0 {
                        let pos = base + mask.trailing_zeros() as usize;
                        if hit(pos) {
                            return;
                        }
                        mask &= mask - 1;
                    }
                }
                last = v3;
                first = false;
                base += 64;
            }
            tail(bytes, prev, input, base, hit);
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod ssse3 {
    use super::{NibbleSet, tail};
    use core::arch::x86_64::*;

    /// As the NEON search: one instantiation per caller.
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn search(
        bytes: &[u8],
        prev: Option<&NibbleSet>,
        input: &[u8],
        mut hit: impl FnMut(usize) -> bool,
    ) {
        let hit = &mut hit;
        let len = input.len();
        let ptr = input.as_ptr();
        let set = prev.unwrap_or(&NibbleSet::ALL);
        // SAFETY: SSSE3 is enabled for this function; every load reads 16
        // bytes inside `input[base..base + 64]`, which the loop condition
        // guarantees.
        unsafe {
            let a = _mm_set1_epi8(bytes[0] as i8);
            let b = _mm_set1_epi8(*bytes.get(1).unwrap_or(&bytes[0]) as i8);
            let c = _mm_set1_epi8(*bytes.get(2).unwrap_or(&bytes[0]) as i8);
            let lo = _mm_loadu_si128(set.lo.as_ptr().cast());
            let hi = _mm_loadu_si128(set.hi.as_ptr().cast());
            let low_nibble = _mm_set1_epi8(0x0F);
            let zero = _mm_setzero_si128();
            let eq = |v: __m128i| -> __m128i {
                _mm_or_si128(
                    _mm_or_si128(_mm_cmpeq_epi8(v, a), _mm_cmpeq_epi8(v, b)),
                    _mm_cmpeq_epi8(v, c),
                )
            };
            // Lanes whose byte is not in the set.
            let outside = |p: __m128i| -> __m128i {
                let l = _mm_shuffle_epi8(lo, _mm_and_si128(p, low_nibble));
                let h = _mm_shuffle_epi8(hi, _mm_and_si128(_mm_srli_epi16::<4>(p), low_nibble));
                _mm_cmpeq_epi8(_mm_and_si128(l, h), zero)
            };
            let mut last = _mm_setzero_si128();
            let mut first = true;
            let mut base = 0;
            while base + 64 <= len {
                let v0 = _mm_loadu_si128(ptr.add(base).cast());
                let v1 = _mm_loadu_si128(ptr.add(base + 16).cast());
                let v2 = _mm_loadu_si128(ptr.add(base + 32).cast());
                let v3 = _mm_loadu_si128(ptr.add(base + 48).cast());
                let mut e0 = eq(v0);
                let mut e1 = eq(v1);
                let mut e2 = eq(v2);
                let mut e3 = eq(v3);
                let any = _mm_or_si128(_mm_or_si128(e0, e1), _mm_or_si128(e2, e3));
                if _mm_movemask_epi8(any) != 0 {
                    let mut o0 = outside(_mm_alignr_epi8::<15>(v0, last));
                    if first {
                        // Position 0 has no previous byte.
                        o0 = _mm_andnot_si128(_mm_cvtsi32_si128(0xFF), o0);
                    }
                    e0 = _mm_andnot_si128(o0, e0);
                    e1 = _mm_andnot_si128(outside(_mm_alignr_epi8::<15>(v1, v0)), e1);
                    e2 = _mm_andnot_si128(outside(_mm_alignr_epi8::<15>(v2, v1)), e2);
                    e3 = _mm_andnot_si128(outside(_mm_alignr_epi8::<15>(v3, v2)), e3);
                    let mut mask = _mm_movemask_epi8(e0) as u16 as u64
                        | (_mm_movemask_epi8(e1) as u16 as u64) << 16
                        | (_mm_movemask_epi8(e2) as u16 as u64) << 32
                        | (_mm_movemask_epi8(e3) as u16 as u64) << 48;
                    while mask != 0 {
                        let pos = base + mask.trailing_zeros() as usize;
                        if hit(pos) {
                            return;
                        }
                        mask &= mask - 1;
                    }
                }
                last = v3;
                first = false;
                base += 64;
            }
            tail(bytes, prev, input, base, hit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(bytes: &[u8], prev: Option<&NibbleSet>, input: &[u8]) -> Vec<usize> {
        (0..input.len())
            .filter(|&pos| bytes.contains(&input[pos]) && qualifies(prev, input, pos))
            .collect()
    }

    fn engines() -> Vec<Engine> {
        let mut engines = vec![Engine::Memchr];
        let detected = Engine::of(crate::classify::detect());
        if detected != Engine::Memchr {
            engines.push(detected);
        }
        engines
    }

    fn check(bytes: &[u8], prev: Option<&NibbleSet>, input: &[u8]) {
        let expected = reference(bytes, prev, input);
        for engine in engines() {
            let mut got = Vec::new();
            search(engine, bytes, prev, input, |pos| {
                got.push(pos);
                false
            });
            assert_eq!(got, expected, "{engine:?} {bytes:?} {input:?}");
        }
    }

    fn set_of(members: &[u8]) -> NibbleSet {
        let mut table = [false; 256];
        for &b in members {
            table[usize::from(b)] = true;
        }
        NibbleSet::new(&table).expect("a proper subset")
    }

    #[test]
    fn nibble_sets_are_exact_up_to_eight_patterns_and_supersets_beyond() {
        let set = set_of(b"apsoAPSO\n");
        for b in 0..=255u8 {
            assert_eq!(set.contains(b), b"apsoAPSO\n".contains(&b), "{b}");
        }
        let mut members = [false; 256];
        for b in (0..=255u8).step_by(7) {
            members[usize::from(b)] = true;
        }
        let set = NibbleSet::new(&members).expect("a proper subset");
        for b in 0..=255u8 {
            assert!(!members[usize::from(b)] || set.contains(b), "{b}");
        }
        assert!(NibbleSet::new(&[true; 256]).is_none());
    }

    #[test]
    fn search_agrees_with_a_scalar_reference() {
        let set = set_of(b"apsoAPSO\n");
        let mut input = Vec::new();
        for i in 0..700u32 {
            input.extend_from_slice(match i % 7 {
                0 => b"10:30:".as_slice(),
                1 => b"https:",
                2 => b" \xC3\xA9:",
                3 => b"\n:",
                4 => b"TODO:x",
                5 => b":@.",
                _ => b"-",
            });
        }
        for len in [0, 1, 2, 63, 64, 65, 127, 128, 129, 200, input.len()] {
            let input = &input[..len.min(input.len())];
            for start in [0, 1, 5] {
                let input = &input[start.min(input.len())..];
                for bytes in [b":".as_slice(), b":@", b".:@"] {
                    check(bytes, None, input);
                    check(bytes, Some(&set), input);
                }
            }
        }
        // A hit at position 0 has no previous byte.
        let mut input = vec![b'x'; 130];
        input[0] = b':';
        input[64] = b':';
        check(b":", Some(&set), &input);
    }

    #[test]
    fn search_stops_when_asked() {
        let input = vec![b':'; 300];
        for engine in engines() {
            let mut seen = 0;
            search(engine, b":", None, &input, |_| {
                seen += 1;
                seen == 70
            });
            assert_eq!(seen, 70, "{engine:?}");
        }
    }
}
