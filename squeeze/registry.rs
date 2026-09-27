//! Case-insensitive lookups in the IANA registries of `iana.rs`.
//!
//! The generated `phf` sets hash with SipHash, whose setup dominates for
//! keys of a few bytes; the scanners look a scheme or a TLD up at nearly
//! every candidate, so the keys are rehashed once into an open-addressing
//! table with a multiplicative hash over 8-byte words.

use std::sync::OnceLock;

pub(crate) struct Registry {
    /// Index + 1 into `keys`, 0 for an empty slot.
    slots: Box<[u16]>,
    keys: Vec<&'static str>,
    shift: u32,
}

const K: u64 = 0x9E37_79B9_7F4A_7C15;
/// Sets bit 5 of every byte, so both cases of a letter hash alike.
const FOLD: u64 = 0x2020_2020_2020_2020;

impl Registry {
    fn new(keys: impl Iterator<Item = &'static str>) -> Self {
        let keys: Vec<&'static str> = keys.collect();
        assert!(keys.len() < usize::from(u16::MAX));
        let size = (keys.len() * 2).next_power_of_two().max(16);
        let mut slots = vec![0u16; size].into_boxed_slice();
        let shift = 64 - size.trailing_zeros();
        for (i, key) in keys.iter().enumerate() {
            let mut slot = Self::slot(key.as_bytes(), shift);
            while slots[slot] != 0 {
                slot = (slot + 1) & (size - 1);
            }
            slots[slot] = i as u16 + 1;
        }
        Registry { slots, keys, shift }
    }

    #[inline(always)]
    fn slot(key: &[u8], shift: u32) -> usize {
        let mut h = key.len() as u64;
        let (words, rest) = key.as_chunks::<8>();
        for &word in words {
            h = (h ^ (u64::from_le_bytes(word) | FOLD))
                .wrapping_mul(K)
                .rotate_left(23);
        }
        if !rest.is_empty() {
            let mut word = [0u8; 8];
            word[..rest.len()].copy_from_slice(rest);
            h = (h ^ (u64::from_le_bytes(word) | FOLD))
                .wrapping_mul(K)
                .rotate_left(23);
        }
        (h.wrapping_mul(K) >> shift) as usize
    }

    /// Whether `key`, ASCII case ignored, is in the registry.
    #[inline]
    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        let mask = self.slots.len() - 1;
        let mut slot = Self::slot(key, self.shift);
        loop {
            match self.slots[slot] {
                0 => return false,
                i if self.keys[usize::from(i) - 1]
                    .as_bytes()
                    .eq_ignore_ascii_case(key) =>
                {
                    return true;
                }
                _ => slot = (slot + 1) & mask,
            }
        }
    }
}

/// Registered URI schemes, lowercase.
pub(crate) fn uri_schemes() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry::new(crate::iana::URI_SCHEMES.iter().copied()))
}

/// Delegated top-level domains, lowercase.
pub(crate) fn tlds() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| Registry::new(crate::iana::TLDS.iter().copied()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registries_agree_with_the_generated_sets() {
        for (registry, set) in [
            (uri_schemes(), &crate::iana::URI_SCHEMES),
            (tlds(), &crate::iana::TLDS),
        ] {
            for key in set.iter() {
                assert!(registry.contains(key.as_bytes()), "{key}");
                assert!(
                    registry.contains(key.to_ascii_uppercase().as_bytes()),
                    "{key}"
                );
                let longer = format!("{key}x");
                assert_eq!(registry.contains(longer.as_bytes()), set.contains(&*longer));
                let shorter = &key[..key.len() - 1];
                assert_eq!(registry.contains(shorter.as_bytes()), set.contains(shorter));
            }
            for key in ["", "a", "zz", "https:", "12345678", "localhost", "\u{e9}"] {
                assert_eq!(
                    registry.contains(key.as_bytes()),
                    set.contains(key),
                    "{key}"
                );
            }
        }
    }
}
