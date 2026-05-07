//! Tests bloqueantes de Fase 1 — generador combinatorio CPU.
//!
//! Estos tests son contrato: si fallan, no se entra en Fase 2.

use std::collections::HashSet;

use proptest::prelude::*;
use quattro_crack::combinatorics::{
    index_to_password, is_well_formed, password_to_index, CONSONANTS, M_YEAR, N, PW_LEN, VOWELS,
};

/// Reproducible "aleatorio": LCG sencillo, sin dependencias extra.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        // Numerical Recipes; ciclo 2^64.
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_in_range(&mut self, n: u64) -> u64 {
        // Sesgado pero suficiente para muestrear.
        self.next_u64() % n
    }
}

#[test]
fn test_index_to_password_unique_first_million() {
    let mut seen: HashSet<[u8; PW_LEN]> = HashSet::with_capacity(1_000_000);
    for idx in 0..1_000_000u64 {
        let pw = index_to_password(idx);
        assert!(
            seen.insert(pw),
            "colisión en idx={idx}: pw={:?} duplicada",
            std::str::from_utf8(&pw).ok()
        );
    }
    assert_eq!(seen.len(), 1_000_000);
}

#[test]
fn test_index_to_password_structure() {
    // Estructura sobre el primer millón.
    for idx in 0..1_000_000u64 {
        let pw = index_to_password(idx);
        assert!(
            is_well_formed(&pw),
            "idx={idx} mal formado: {:?}",
            std::str::from_utf8(&pw).ok()
        );
    }
}

#[test]
fn test_round_trip_idx_pw_idx_1k_random() {
    // 1000 índices aleatorios en [0, N).
    let mut rng = Rng::new(0x00C0_FFEE_BADD_ECAF);
    for _ in 0..1_000 {
        let idx = rng.next_in_range(N);
        let pw = index_to_password(idx);
        let back = password_to_index(&pw).expect("roundtrip parse");
        assert_eq!(idx, back, "roundtrip falló en idx={idx}");
    }
}

#[test]
fn test_round_trip_full_10k() {
    // 10 000 índices aleatorios — confirma masa.
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..10_000 {
        let idx = rng.next_in_range(N);
        let pw = index_to_password(idx);
        let back = password_to_index(&pw).unwrap();
        assert_eq!(idx, back);
    }
}

#[test]
fn test_documented_endpoints() {
    assert_eq!(&index_to_password(0), b".aAaabbbb1000.");
    assert_eq!(&index_to_password(N - 1), b".zzzzuuuU1999.");
}

#[test]
fn test_year_field_is_top_weight() {
    // Cambiar `year` en 1 ⇒ idx cambia en exactamente M_YEAR.
    let p_year_0 = index_to_password(0);
    let p_year_1 = index_to_password(M_YEAR);
    // El password con year=1 debe ser idéntico salvo el último trío de dígitos.
    for i in 0..10 {
        assert_eq!(p_year_0[i], p_year_1[i]);
    }
    assert_eq!(&p_year_0[10..13], b"000");
    assert_eq!(&p_year_1[10..13], b"001");
    assert_eq!(p_year_0[13], b'.');
    assert_eq!(p_year_1[13], b'.');
}

#[test]
fn test_alphabets_are_disjoint_and_complete() {
    // Vocales y consonantes no se solapan y cubren las 26 letras ASCII.
    for &v in VOWELS.iter() {
        assert!(
            !CONSONANTS.contains(&v),
            "{} no debe estar en consonantes",
            v as char
        );
    }
    let mut all = Vec::new();
    all.extend_from_slice(VOWELS);
    all.extend_from_slice(CONSONANTS);
    all.sort();
    let alphabet: Vec<u8> = (b'a'..=b'z').collect();
    assert_eq!(all, alphabet, "VOWELS ∪ CONSONANTS debe ser [a..z]");
}

proptest! {
    /// Property: cualquier idx legal genera un password bien formado y la
    /// inversa devuelve el mismo idx.
    #[test]
    fn prop_roundtrip(idx in 0u64..N) {
        let pw = index_to_password(idx);
        prop_assert!(is_well_formed(&pw));
        prop_assert_eq!(password_to_index(&pw).unwrap(), idx);
    }

    /// Property: la longitud siempre es 14 y los frame chars son fijos.
    #[test]
    fn prop_frame_invariants(idx in 0u64..N) {
        let pw = index_to_password(idx);
        prop_assert_eq!(pw.len(), PW_LEN);
        prop_assert_eq!(pw[0], b'.');
        prop_assert_eq!(pw[9], b'1');
        prop_assert_eq!(pw[13], b'.');
    }

    /// Property: bloque de letras contiene exactamente 4 vocales y exactamente
    /// 1 mayúscula que no está en pos 1 (=primera del bloque).
    #[test]
    fn prop_letter_constraints(idx in 0u64..N) {
        let pw = index_to_password(idx);
        let letters = &pw[1..9];
        let upper_count = letters.iter().filter(|c| c.is_ascii_uppercase()).count();
        prop_assert_eq!(upper_count, 1);
        prop_assert!(!letters[0].is_ascii_uppercase());
        let vowel_count = letters
            .iter()
            .filter(|c| VOWELS.contains(&c.to_ascii_lowercase()))
            .count();
        prop_assert_eq!(vowel_count, 4);
    }
}
