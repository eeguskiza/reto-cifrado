//! Generador combinatorio bijectivo `idx ↔ password`.
//!
//! Estructura del password (ver `DECISIONS.md` D-002):
//!
//! ```text
//!  pos:  0 1 2 3 4 5 6 7 8 9 10 11 12 13
//!        . L L L L L L L L 1 N  N  N  .
//! ```
//!
//! Las 8 letras (pos 1..9) tienen exactamente 4 vocales (`aeiou`) +
//! 4 consonantes (las 21 ASCII restantes), y exactamente 1 mayúscula
//! que **no** está en pos 1 (= primera del bloque de letras).
//!
//! Decomposición en cinco campos de mayor a menor peso:
//!
//! ```text
//!   year (1000)  ·  disp (70)  ·  upper (7)  ·  cons (21⁴)  ·  vowel (5⁴)
//! ```
//!
//! Endpoints documentados:
//!
//! - `idx = 0`     → `.aAaabbbb1000.`
//! - `idx = N - 1` → `.zzzzuuuU1999.`

use thiserror::Error;

/// Vocales válidas en cualquier posición de vocal del bloque de 8 letras.
pub const VOWELS: &[u8; 5] = b"aeiou";
/// Consonantes válidas (las 21 letras ASCII restantes tras quitar vocales).
pub const CONSONANTS: &[u8; 21] = b"bcdfghjklmnpqrstvwxyz";

/// Longitud fija del password en bytes ASCII (incluye los `.` y el `1` literal).
pub const PW_LEN: usize = 14;

/// Cardinalidad del campo `year` (3 dígitos `NNN` ∈ 000..999).
pub const N_YEAR: u64 = 1_000;
/// Cardinalidad del campo `disp` (`C(8,4) = 70` disposiciones de vocales).
pub const N_DISP: u64 = 70;
/// Cardinalidad del campo `upper` (7 posiciones válidas de la mayúscula).
pub const N_UPPER: u64 = 7;
/// Cardinalidad del campo `cons` (`21⁴ = 194 481` combos de consonantes).
pub const N_CONS: u64 = 21 * 21 * 21 * 21;
/// Cardinalidad del campo `vowel` (`5⁴ = 625` combos de vocales).
pub const N_VOWEL: u64 = 5 * 5 * 5 * 5;

/// Multiplicador acumulado de `vowel` (LSB del idx).
pub const M_VOWEL: u64 = 1;
/// Multiplicador acumulado de `cons` (= `N_VOWEL`).
pub const M_CONS: u64 = N_VOWEL;
/// Multiplicador acumulado de `upper` (= 121 550 625).
pub const M_UPPER: u64 = N_CONS * N_VOWEL;
/// Multiplicador acumulado de `disp` (= 850 854 375).
pub const M_DISP: u64 = N_UPPER * M_UPPER;
/// Multiplicador acumulado de `year` — peso mayor (= 59 559 806 250).
pub const M_YEAR: u64 = N_DISP * M_DISP;

/// Cardinalidad total del espacio combinatorio (≈ 5,96 × 10¹³). Ver D-001.
pub const N: u64 = N_YEAR * M_YEAR;

/// 70 disposiciones lexicográficas de `C(8, 4)`: qué 4 posiciones del bloque
/// de 8 letras (0-indexado) llevan vocal. Las otras 4 llevan consonante.
const DISPOSITIONS: [[u8; 4]; 70] = build_dispositions();

const fn build_dispositions() -> [[u8; 4]; 70] {
    let mut out = [[0u8; 4]; 70];
    let mut idx = 0usize;
    let mut a: u8 = 0;
    while a < 5 {
        let mut b: u8 = a + 1;
        while b < 6 {
            let mut c: u8 = b + 1;
            while c < 7 {
                let mut d: u8 = c + 1;
                while d < 8 {
                    out[idx] = [a, b, c, d];
                    idx += 1;
                    d += 1;
                }
                c += 1;
            }
            b += 1;
        }
        a += 1;
    }
    // Sanity (compile-time): si la enumeración no cubre 70, ¡rompe el build!
    debug_assert!(idx == 70);
    out
}

/// Errores al parsear un password en su índice.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Las posiciones literal `.LLLLLLLL1NNN.` (índices 0, 9, 13) no
    /// contienen los caracteres esperados.
    #[error("frame inválido: pos 0/9/13 deben ser '.', '1', '.'")]
    Frame,
    /// La posición indicada (en el bloque `NNN`) no es un dígito ASCII.
    #[error("posición {0} no es dígito")]
    NotDigit(usize),
    /// La posición indicada (en el bloque de 8 letras) no es ASCII alfabético.
    #[error("posición {0} no es letra ASCII")]
    NotLetter(usize),
    /// El bloque de 8 letras no contiene exactamente 1 mayúscula.
    #[error("número de mayúsculas != 1")]
    UppercaseCount,
    /// La única mayúscula está en `letters[0]` (posición 0 del bloque),
    /// que no es válida según el espacio del reto.
    #[error("la única mayúscula está en la primera letra (no permitido)")]
    UppercaseAtFirst,
    /// El bloque de 8 letras no contiene exactamente 4 vocales (`aeiou`).
    #[error("número de vocales != 4")]
    VowelCount,
    /// La letra en esa posición no pertenece ni a `VOWELS` ni a
    /// `CONSONANTS` (p. ej., una vocal acentuada o letra fuera de ASCII).
    #[error("posición {0} no es vocal de aeiou ni consonante de las 21 ASCII")]
    InvalidLetter(usize),
}

/// `idx → password`. `idx` debe estar en `[0, N)`.
///
/// # Panics
///
/// Si `idx >= N`. Esa precondición la verifica el caller (kernel y CPU).
pub fn index_to_password(idx: u64) -> [u8; PW_LEN] {
    assert!(idx < N, "idx={idx} fuera del rango [0, {N})");

    let year = idx / M_YEAR;
    let r1 = idx % M_YEAR;
    let disp = (r1 / M_DISP) as usize;
    let r2 = r1 % M_DISP;
    let upper = (r2 / M_UPPER) as usize;
    let r3 = r2 % M_UPPER;
    let cons = r3 / M_CONS;
    let vowel = r3 % M_CONS;

    let vowel_positions = DISPOSITIONS[disp];

    // Decodifica los 4 dígitos base 5 de `vowel` con dígito más significativo
    // primero (asignado a la posición de vocal más a la izquierda).
    let vd = decompose_base::<4>(vowel, 5);
    let cd = decompose_base::<4>(cons, 21);

    let mut letters = [0u8; 8];

    for (i, &pos) in vowel_positions.iter().enumerate() {
        letters[pos as usize] = VOWELS[vd[i] as usize];
    }

    // Posiciones de consonantes = complemento de `vowel_positions` en 0..8.
    let mut cons_positions = [0u8; 4];
    let vp_mask: u8 = vowel_positions.iter().fold(0u8, |acc, &p| acc | (1 << p));
    let mut k = 0usize;
    for p in 0u8..8 {
        if (vp_mask & (1 << p)) == 0 {
            cons_positions[k] = p;
            k += 1;
        }
    }
    debug_assert_eq!(k, 4);

    for (i, &pos) in cons_positions.iter().enumerate() {
        letters[pos as usize] = CONSONANTS[cd[i] as usize];
    }

    // Aplica mayúscula en `letters[upper + 1]` (offset que excluye la posición 0).
    let upos = upper + 1;
    letters[upos] = letters[upos].to_ascii_uppercase();

    // Ensambla password completo.
    let mut pw = [b'.'; PW_LEN];
    pw[0] = b'.';
    pw[1..9].copy_from_slice(&letters);
    pw[9] = b'1';
    let y = year as u32;
    pw[10] = b'0' + ((y / 100) % 10) as u8;
    pw[11] = b'0' + ((y / 10) % 10) as u8;
    pw[12] = b'0' + (y % 10) as u8;
    pw[13] = b'.';
    pw
}

/// `password → idx`. Inversa de [`index_to_password`].
pub fn password_to_index(pw: &[u8; PW_LEN]) -> Result<u64, ParseError> {
    if pw[0] != b'.' || pw[9] != b'1' || pw[13] != b'.' {
        return Err(ParseError::Frame);
    }
    for (i, c) in pw.iter().enumerate().take(13).skip(10) {
        if !c.is_ascii_digit() {
            return Err(ParseError::NotDigit(i));
        }
    }
    let year = (pw[10] - b'0') as u64 * 100 + (pw[11] - b'0') as u64 * 10 + (pw[12] - b'0') as u64;

    let letters = &pw[1..9];
    for (i, &c) in letters.iter().enumerate() {
        if !c.is_ascii_alphabetic() {
            return Err(ParseError::NotLetter(1 + i));
        }
    }

    let upper_count = letters.iter().filter(|c| c.is_ascii_uppercase()).count();
    if upper_count != 1 {
        return Err(ParseError::UppercaseCount);
    }
    let upper_in_block = letters
        .iter()
        .position(|c| c.is_ascii_uppercase())
        .expect("upper_count == 1");
    if upper_in_block == 0 {
        return Err(ParseError::UppercaseAtFirst);
    }
    let upper = (upper_in_block - 1) as u64;

    // Lowercased copy.
    let mut lc = [0u8; 8];
    for (i, &c) in letters.iter().enumerate() {
        lc[i] = c.to_ascii_lowercase();
    }

    // Identifica vocales/consonantes y rechaza letras no incluidas en los
    // alfabetos del problema.
    let mut vowel_positions = [0u8; 4];
    let mut vp_n = 0usize;
    for (i, &c) in lc.iter().enumerate() {
        if VOWELS.contains(&c) {
            if vp_n < 4 {
                vowel_positions[vp_n] = i as u8;
            }
            vp_n += 1;
        } else if !CONSONANTS.contains(&c) {
            return Err(ParseError::InvalidLetter(1 + i));
        }
    }
    if vp_n != 4 {
        return Err(ParseError::VowelCount);
    }

    let disp = DISPOSITIONS
        .iter()
        .position(|d| *d == vowel_positions)
        .expect("vowel_positions están en 0..8 ordenadas: hay disposición") as u64;

    // Reconstruye los valores base-5 (vocales) y base-21 (consonantes).
    // Convención MSB-first: la posición de vocal/consonante más baja
    // corresponde al dígito más significativo.
    let mut vowel_value: u64 = 0;
    for &pos in vowel_positions.iter() {
        let c = lc[pos as usize];
        let v_idx = VOWELS
            .iter()
            .position(|&v| v == c)
            .expect("c es vocal por construcción") as u64;
        vowel_value = vowel_value * 5 + v_idx;
    }

    let mut cons_value: u64 = 0;
    for p in 0u8..8 {
        if !vowel_positions.contains(&p) {
            let c = lc[p as usize];
            let c_idx = CONSONANTS
                .iter()
                .position(|&v| v == c)
                .expect("c es consonante por construcción") as u64;
            cons_value = cons_value * 21 + c_idx;
        }
    }

    Ok(year * M_YEAR + disp * M_DISP + upper * M_UPPER + cons_value * M_CONS + vowel_value)
}

/// Verifica que `pw` cumple la estructura del espacio de búsqueda.
pub fn is_well_formed(pw: &[u8; PW_LEN]) -> bool {
    password_to_index(pw).is_ok()
}

/// Descompone `value` en `K` dígitos en base `base`, MSB primero.
fn decompose_base<const K: usize>(value: u64, base: u64) -> [u8; K] {
    let mut out = [0u8; K];
    let mut v = value;
    let mut place: u64 = 1;
    for _ in 1..K {
        place *= base;
    }
    for slot in out.iter_mut() {
        *slot = (v / place) as u8;
        v %= place;
        if place >= base {
            place /= base;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cardinality_matches_factors() {
        assert_eq!(N, 70 * 625 * 194_481 * 7 * 1_000);
        assert_eq!(N, 59_559_806_250_000);
    }

    #[test]
    fn dispositions_first_and_last() {
        assert_eq!(DISPOSITIONS[0], [0, 1, 2, 3]);
        assert_eq!(DISPOSITIONS[69], [4, 5, 6, 7]);
    }

    #[test]
    fn dispositions_count_70_and_strictly_increasing() {
        assert_eq!(DISPOSITIONS.len(), 70);
        for d in &DISPOSITIONS {
            assert!(d[0] < d[1] && d[1] < d[2] && d[2] < d[3]);
            assert!(d[3] < 8);
        }
        // Y no se repiten:
        let mut sorted: Vec<[u8; 4]> = DISPOSITIONS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 70);
    }

    #[test]
    fn idx_zero_endpoint() {
        let pw = index_to_password(0);
        assert_eq!(&pw, b".aAaabbbb1000.");
    }

    #[test]
    fn idx_n_minus_one_endpoint() {
        let pw = index_to_password(N - 1);
        assert_eq!(&pw, b".zzzzuuuU1999.");
    }

    #[test]
    fn roundtrip_endpoints() {
        assert_eq!(password_to_index(&index_to_password(0)).unwrap(), 0);
        assert_eq!(password_to_index(&index_to_password(N - 1)).unwrap(), N - 1);
    }

    #[test]
    fn well_formed_endpoints() {
        assert!(is_well_formed(&index_to_password(0)));
        assert!(is_well_formed(&index_to_password(N - 1)));
    }

    #[test]
    fn decompose_base_msb_first() {
        // 624 = 4*125 + 4*25 + 4*5 + 4 → [4,4,4,4]
        assert_eq!(decompose_base::<4>(624, 5), [4, 4, 4, 4]);
        // 1 = 0,0,0,1
        assert_eq!(decompose_base::<4>(1, 5), [0, 0, 0, 1]);
        // 5 = 0,0,1,0
        assert_eq!(decompose_base::<4>(5, 5), [0, 0, 1, 0]);
        assert_eq!(decompose_base::<4>(0, 21), [0, 0, 0, 0]);
    }

    #[test]
    fn structure_of_some_indices() {
        // Algunos índices clave a través del espacio.
        for &idx in &[0u64, 1, 624, 625, M_CONS, M_UPPER, M_DISP, M_YEAR, N - 1] {
            let pw = index_to_password(idx);
            assert!(
                is_well_formed(&pw),
                "idx={idx} produjo pw mal formado: {:?}",
                std::str::from_utf8(&pw).unwrap_or("<no utf8>")
            );
            assert_eq!(password_to_index(&pw).unwrap(), idx, "roundtrip idx={idx}");
        }
    }

    #[test]
    fn idx_just_after_zero_increments_lowest_field() {
        // idx=1 debe diferir solo en la última vocal (1 → e en lugar de a)
        let p0 = index_to_password(0);
        let p1 = index_to_password(1);
        // Posición de la última vocal en idx=0: disp=0 → vowel_positions=[0,1,2,3]
        // → la "última" vocal (MSB→LSB → última = pos 3 del bloque = pos 4 del pw)
        // El generador asigna la más-significativa a la primera posición de vocal
        // (pos 0 del bloque), por lo que LSB va en la última (pos 3).
        // Bytes del bloque que cambian: pw[1+3] = pw[4]
        for i in 0..PW_LEN {
            if i == 4 {
                assert_ne!(p0[i], p1[i], "idx=1 debe diferir en la última vocal");
            } else {
                assert_eq!(p0[i], p1[i], "idx=1 sólo debe cambiar la última vocal");
            }
        }
    }
}
