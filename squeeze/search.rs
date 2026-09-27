//! The byte search of a `memchr` pass: every position holding one of up to
//! three bytes, optionally only where the byte before it belongs to a set.
//!
//! `memchr_iter` restarts its vector loop after every hit, which dominates
//! when hits are dense (the colons of timestamps in a log). This search
//! takes a mask per 64 bytes and walks its bits, and tests the previous
//! byte of every hit in the same vectors, so a colon after a digit never
//! reaches the scanner when no finder of the pass can start there.

/// Heuristic frequency rank of each byte in typical text, higher is more
/// frequent: the table of the `memchr` crate's substring search.
#[rustfmt::skip]
const RANK: [u8; 256] = [
     55,  52,  51,  50,  49,  48,  47,  46,  45, 103, 242,  66,  67, 229,  44,  43,
     42,  41,  40,  39,  38,  37,  36,  35,  34,  33,  56,  32,  31,  30,  29,  28,
    255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122, 232, 202, 215, 224,
    208, 220, 204, 187, 183, 179, 177, 168, 178, 200, 226, 195, 154, 184, 174, 126,
    120, 191, 157, 194, 170, 189, 162, 161, 150, 193, 142, 137, 171, 176, 185, 167,
    186, 112, 175, 192, 188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223,
    151, 249, 216, 238, 236, 253, 227, 218, 230, 247, 135, 180, 241, 233, 246, 244,
    231, 139, 245, 243, 251, 235, 201, 196, 240, 214, 152, 182, 205, 181, 127,  27,
    212, 211, 210, 213, 228, 197, 169, 159, 131, 172, 105,  80,  98,  96,  97,  81,
    207, 145, 116, 115, 144, 130, 153, 121, 107, 132, 109, 110, 124, 111,  82, 108,
    118, 141, 113, 129, 119, 125, 165, 117,  92, 106,  83,  72,  99,  93,  65,  79,
    166, 237, 163, 199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248, 158, 239,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

/// How frequent the most frequent of `bytes` is expected to be: of two
/// searches, the one with the lower rank finds fewer hits.
pub(crate) fn rank(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .map(|&b| RANK[usize::from(b)])
        .max()
        .unwrap_or(0)
}

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

/// Most checks a search tests.
pub(crate) const MAX_CHECKS: usize = 4;

/// A condition on the hits of some searched bytes, tested on the search's
/// bit masks: the bytes `offsets` after a hit must be searched bytes listed
/// in `bytes`, at every offset with `all` and at one of them otherwise.
/// `hits` and `bytes` are bit sets over the indices of the searched bytes;
/// offsets are below 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Check {
    pub(crate) hits: u8,
    pub(crate) bytes: u8,
    pub(crate) offsets: [u8; crate::MAX_CHECK_OFFSETS],
    pub(crate) count: u8,
    pub(crate) all: bool,
}

impl Check {
    fn offsets(&self) -> &[u8] {
        &self.offsets[..usize::from(self.count)]
    }

    /// Hits of the group whose masks are `cur` passing the check, `next`
    /// holding the masks of the following 64 bytes.
    #[inline(always)]
    fn pass(&self, cur: &[u64; 3], next: &[u64; 3]) -> u64 {
        let (mut now, mut then) = (0u64, 0u64);
        for j in 0..3 {
            if self.bytes & (1 << j) != 0 {
                now |= cur[j];
                then |= next[j];
            }
        }
        let window = u128::from(now) | u128::from(then) << 64;
        let mut pass = if self.all { u64::MAX } else { 0 };
        for &offset in self.offsets() {
            let shifted = (window >> offset) as u64;
            pass = if self.all {
                pass & shifted
            } else {
                pass | shifted
            };
        }
        pass
    }
}

/// The checks of a search: a hit of a searched byte whose index is set in
/// `conditional` must pass one of the checks listing it in `hits`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Checks {
    pub(crate) conditional: u8,
    pub(crate) list: [Option<Check>; MAX_CHECKS],
}

impl Checks {
    /// Hits among `cur` (masks per searched byte) that pass.
    #[inline(always)]
    fn keep(&self, cur: &[u64; 3], next: &[u64; 3]) -> u64 {
        let mut keep = 0u64;
        for k in 0..3 {
            if cur[k] == 0 {
                continue;
            }
            if self.conditional & (1 << k) == 0 {
                keep |= cur[k];
                continue;
            }
            let mut pass = 0u64;
            for check in self.list.iter().flatten() {
                if check.hits & (1 << k) != 0 {
                    pass |= check.pass(cur, next);
                }
            }
            keep |= cur[k] & pass;
        }
        keep
    }

    /// Whether the hit at `pos` passes, scalar.
    fn survives(&self, bytes: &[u8], input: &[u8], pos: usize) -> bool {
        let Some(k) = bytes.iter().position(|&b| b == input[pos]) else {
            return false;
        };
        if self.conditional & (1 << k) == 0 {
            return true;
        }
        self.list.iter().flatten().any(|check| {
            if check.hits & (1 << k) == 0 {
                return false;
            }
            let listed = |offset: &u8| {
                input.get(pos + usize::from(*offset)).is_some_and(|&b| {
                    bytes
                        .iter()
                        .enumerate()
                        .any(|(j, &searched)| check.bytes & (1 << j) != 0 && searched == b)
                })
            };
            if check.all {
                check.offsets().iter().all(listed)
            } else {
                check.offsets().iter().any(listed)
            }
        })
    }
}

/// Calls `hit` with every position of `input` holding one of `bytes` (one
/// to three) whose previous byte is in `prev`, when given, and that passes
/// `checks`; position 0 has no previous byte and always qualifies. Stops
/// when `hit` returns `true`.
#[inline(always)]
pub(crate) fn search(
    engine: Engine,
    bytes: &[u8],
    prev: Option<&NibbleSet>,
    checks: &Checks,
    input: &[u8],
    mut hit: impl FnMut(usize) -> bool,
) {
    debug_assert!((1..=3).contains(&bytes.len()));
    if checks.conditional != 0 {
        match engine {
            Engine::Memchr => memchr_search(bytes, prev, input, |pos| {
                checks.survives(bytes, input, pos) && hit(pos)
            }),
            #[cfg(target_arch = "aarch64")]
            Engine::Neon => checked(bytes, prev, checks, input, neon::masks, hit),
            #[cfg(target_arch = "x86_64")]
            Engine::Ssse3 => checked(
                bytes,
                prev,
                checks,
                input,
                // SAFETY: `Engine::Ssse3` is only selected after the CPU
                // check.
                |input, base, bytes, set| unsafe { ssse3::masks(input, base, bytes, set) },
                hit,
            ),
        }
        return;
    }
    match engine {
        Engine::Memchr => memchr_search(bytes, prev, input, hit),
        #[cfg(target_arch = "aarch64")]
        Engine::Neon => neon::search(bytes, prev, input, hit),
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `Engine::Ssse3` is only selected after the CPU check.
        Engine::Ssse3 => unsafe { ssse3::search(bytes, prev, input, hit) },
    }
}

/// Masks of one group of 64 bytes at `base`: per searched byte, and of the
/// positions whose previous byte is in the set (position 0 included).
type GroupMasks = ([u64; 3], u64);

/// The search with checks: each group's masks are kept until the next
/// group's are known, since a check looks up to 63 bytes ahead.
#[inline(always)]
fn checked(
    bytes: &[u8],
    prev: Option<&NibbleSet>,
    checks: &Checks,
    input: &[u8],
    masks: impl Fn(&[u8], usize, &[u8], &NibbleSet) -> GroupMasks,
    mut hit: impl FnMut(usize) -> bool,
) {
    let set = prev.unwrap_or(&NibbleSet::ALL);
    let len = input.len();
    let mut emit = |base: usize, cur: &GroupMasks, next: &[u64; 3]| -> bool {
        let mut mask = checks.keep(&cur.0, next) & cur.1;
        while mask != 0 {
            if hit(base + mask.trailing_zeros() as usize) {
                return true;
            }
            mask &= mask - 1;
        }
        false
    };
    let mut pending: Option<(usize, GroupMasks)> = None;
    let mut base = 0;
    while base + 64 <= len {
        let group = masks(input, base, bytes, set);
        if let Some((at, cur)) = pending
            && emit(at, &cur, &group.0)
        {
            return;
        }
        pending = Some((base, group));
        base += 64;
    }
    // The partial group's masks, for the checks of the last whole one.
    let mut rest = [0u64; 3];
    for (i, &b) in input[base..].iter().enumerate() {
        for (k, &searched) in bytes.iter().enumerate() {
            if b == searched {
                rest[k] |= 1 << i;
            }
        }
    }
    if let Some((at, cur)) = pending
        && emit(at, &cur, &rest)
    {
        return;
    }
    for pos in base..len {
        if bytes.contains(&input[pos])
            && qualifies(prev, input, pos)
            && checks.survives(bytes, input, pos)
            && hit(pos)
        {
            return;
        }
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
    use super::{GroupMasks, NibbleSet, tail};
    use core::arch::aarch64::*;

    const WEIGHTS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];

    /// One bit per byte of four 0x00/0xFF vectors: weigh each lane by its
    /// bit and add neighbours pairwise until each byte holds eight lanes.
    #[inline(always)]
    fn movemask(e: [uint8x16_t; 4]) -> u64 {
        // SAFETY: baseline NEON.
        unsafe {
            let weights = vld1q_u8(WEIGHTS.as_ptr());
            let s01 = vpaddq_u8(vandq_u8(e[0], weights), vandq_u8(e[1], weights));
            let s23 = vpaddq_u8(vandq_u8(e[2], weights), vandq_u8(e[3], weights));
            let s = vpaddq_u8(s01, s23);
            let s = vpaddq_u8(s, s);
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(s))
        }
    }

    /// The masks of the 64 bytes at `base`, which must lie in `input`.
    #[inline(always)]
    pub(super) fn masks(input: &[u8], base: usize, bytes: &[u8], set: &NibbleSet) -> GroupMasks {
        debug_assert!(base + 64 <= input.len());
        let ptr = input.as_ptr();
        // SAFETY: baseline NEON; the loads read `input[base - 1..base + 64]`
        // (from `base` on at the start of the input).
        unsafe {
            let v = [
                vld1q_u8(ptr.add(base)),
                vld1q_u8(ptr.add(base + 16)),
                vld1q_u8(ptr.add(base + 32)),
                vld1q_u8(ptr.add(base + 48)),
            ];
            let mut eq = [0u64; 3];
            for (k, &b) in bytes.iter().enumerate() {
                let splat = vdupq_n_u8(b);
                eq[k] = movemask(v.map(|v| vceqq_u8(v, splat)));
            }
            let lo = vld1q_u8(set.lo.as_ptr());
            let hi = vld1q_u8(set.hi.as_ptr());
            let low_nibble = vdupq_n_u8(0x0F);
            let member = |p: uint8x16_t| -> uint8x16_t {
                let l = vqtbl1q_u8(lo, vandq_u8(p, low_nibble));
                let h = vqtbl1q_u8(hi, vshrq_n_u8::<4>(p));
                vtstq_u8(l, h)
            };
            let first = if base == 0 {
                vextq_u8::<15>(vdupq_n_u8(0), v[0])
            } else {
                vld1q_u8(ptr.add(base - 1))
            };
            let prev = [
                first,
                vld1q_u8(ptr.add(base + 15)),
                vld1q_u8(ptr.add(base + 31)),
                vld1q_u8(ptr.add(base + 47)),
            ];
            let mut after = movemask(prev.map(member));
            if base == 0 {
                after |= 1;
            }
            (eq, after)
        }
    }

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
    use super::{GroupMasks, NibbleSet, tail};
    use core::arch::x86_64::*;

    /// The masks of the 64 bytes at `base`, which must lie in `input`.
    #[target_feature(enable = "ssse3")]
    pub(super) fn masks(input: &[u8], base: usize, bytes: &[u8], set: &NibbleSet) -> GroupMasks {
        debug_assert!(base + 64 <= input.len());
        let ptr = input.as_ptr();
        let movemask = |e: [__m128i; 4]| -> u64 {
            e.iter().enumerate().fold(0u64, |mask, (i, &v)| {
                mask | u64::from(_mm_movemask_epi8(v) as u16) << (16 * i)
            })
        };
        // SAFETY: SSSE3 is enabled for this function; the loads read
        // `input[base - 1..base + 64]` (from `base` on at the start of the
        // input).
        unsafe {
            let v = [
                _mm_loadu_si128(ptr.add(base).cast()),
                _mm_loadu_si128(ptr.add(base + 16).cast()),
                _mm_loadu_si128(ptr.add(base + 32).cast()),
                _mm_loadu_si128(ptr.add(base + 48).cast()),
            ];
            let mut eq = [0u64; 3];
            for (k, &b) in bytes.iter().enumerate() {
                let splat = _mm_set1_epi8(b as i8);
                eq[k] = movemask(v.map(|v| _mm_cmpeq_epi8(v, splat)));
            }
            let lo = _mm_loadu_si128(set.lo.as_ptr().cast());
            let hi = _mm_loadu_si128(set.hi.as_ptr().cast());
            let low_nibble = _mm_set1_epi8(0x0F);
            let zero = _mm_setzero_si128();
            // Lanes whose byte is in the set.
            let member = |p: __m128i| -> __m128i {
                let l = _mm_shuffle_epi8(lo, _mm_and_si128(p, low_nibble));
                let h = _mm_shuffle_epi8(hi, _mm_and_si128(_mm_srli_epi16::<4>(p), low_nibble));
                _mm_andnot_si128(_mm_cmpeq_epi8(_mm_and_si128(l, h), zero), _mm_set1_epi8(-1))
            };
            let first = if base == 0 {
                _mm_slli_si128::<1>(v[0])
            } else {
                _mm_loadu_si128(ptr.add(base - 1).cast())
            };
            let prev = [
                first,
                _mm_loadu_si128(ptr.add(base + 15).cast()),
                _mm_loadu_si128(ptr.add(base + 31).cast()),
                _mm_loadu_si128(ptr.add(base + 47).cast()),
            ];
            let mut after = movemask(prev.map(member));
            if base == 0 {
                after |= 1;
            }
            (eq, after)
        }
    }

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

    fn reference(
        bytes: &[u8],
        prev: Option<&NibbleSet>,
        checks: &Checks,
        input: &[u8],
    ) -> Vec<usize> {
        (0..input.len())
            .filter(|&pos| {
                bytes.contains(&input[pos])
                    && qualifies(prev, input, pos)
                    && checks.survives(bytes, input, pos)
            })
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
        check_with(bytes, prev, &Checks::default(), input);
    }

    fn check_with(bytes: &[u8], prev: Option<&NibbleSet>, checks: &Checks, input: &[u8]) {
        let expected = reference(bytes, prev, checks, input);
        for engine in engines() {
            let mut got = Vec::new();
            search(engine, bytes, prev, checks, input, |pos| {
                got.push(pos);
                false
            });
            assert_eq!(got, expected, "{engine:?} {bytes:?} {checks:?} {input:?}");
        }
    }

    fn periodic(hits: u8, bytes: u8, offsets: &[u8], all: bool) -> Check {
        let mut list = [0u8; crate::MAX_CHECK_OFFSETS];
        list[..offsets.len()].copy_from_slice(offsets);
        Check {
            hits,
            bytes,
            offsets: list,
            count: offsets.len() as u8,
            all,
        }
    }

    #[test]
    fn checked_search_agrees_with_a_scalar_reference() {
        // Searched bytes `-`, `.`, `:` (indices 0, 1, 2), as for MAC
        // addresses: `:` and `-` need separators 3, 6, 9 and 12 bytes on,
        // `.` a dot 5 bytes on or (any of) 2 to 4 bytes on.
        let mac = Checks {
            conditional: 0b111,
            list: [
                Some(periodic(0b101, 0b101, &[3, 6, 9, 12], true)),
                Some(periodic(0b010, 0b010, &[5], true)),
                Some(periodic(0b010, 0b010, &[2, 3, 4], false)),
                None,
            ],
        };
        // Only `-` conditional, UUID dashes.
        let uuid = Checks {
            conditional: 0b001,
            list: [
                Some(periodic(0b001, 0b001, &[5, 10, 15], true)),
                None,
                None,
                None,
            ],
        };
        let set = set_of(b"0123456789abcdef\n");
        let mut input = Vec::new();
        for i in 0..400u32 {
            input.extend_from_slice(match i % 9 {
                0 => b"00:1a:2b:3c:4d:5e ".as_slice(),
                1 => b"10:30:00Z ",
                2 => b"2024-09-24 ",
                3 => b"550e8400-e29b-41d4-a716-446655440000 ",
                4 => b"001a.2b3c.4d5e ",
                5 => b"1.2.3.4 ",
                6 => b"a-b-c-d-e-f-g-h ",
                7 => b"\n-:.",
                _ => b"x",
            });
        }
        for len in [
            0,
            1,
            13,
            63,
            64,
            65,
            100,
            127,
            128,
            129,
            191,
            192,
            193,
            input.len(),
        ] {
            let input = &input[..len.min(input.len())];
            for start in [0, 1, 7, 33] {
                let input = &input[start.min(input.len())..];
                for checks in [&mac, &uuid] {
                    check_with(b"-.:", None, checks, input);
                    check_with(b"-.:", Some(&set), checks, input);
                }
                check_with(b"-", None, &uuid, input);
                check_with(b"-", Some(&set), &uuid, input);
            }
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
            search(engine, b":", None, &Checks::default(), &input, |_| {
                seen += 1;
                seen == 70
            });
            assert_eq!(seen, 70, "{engine:?}");
        }
    }
}
