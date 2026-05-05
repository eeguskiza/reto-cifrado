//! `test_default_plan_order_is_42_cbc_configs` — el plan exhaustivo tiene
//! exactamente 42 entradas en el orden documentado y las primeras 27
//! coinciden byte-a-byte con el orden de Fase 3 (contrato D-013).

use quattro_crack::config::{ConfigEntry, IvSource, Kdf, Mode};
use quattro_crack::plan::{default_plan_order, Preset};

fn cfg(kdf: Kdf, iv: IvSource) -> ConfigEntry {
    ConfigEntry::new(kdf, iv)
}

/// Las 27 entries originales de Fase 3, en el orden v3 inalterado.
fn original_27() -> Vec<ConfigEntry> {
    use IvSource::*;
    use Kdf::*;
    [
        (Md5Utf8, First16),
        (Md5Utf16Le, First16),
        (Md5Utf8, Zeros),
        (Md5Utf8, Md5Pw),
        (Md5x2Utf8, First16),
        (PwPadded, First16),
        (Md5Utf16Le, Zeros),
        (Md5Utf16Le, Md5Pw),
        (Md5x2Utf8, Zeros),
        (Md5x2Utf8, Md5Pw),
        (PwPadded, Zeros),
        (PwPadded, Md5Pw),
        (Md5Utf16Be, First16),
        (Md5Utf16Be, Zeros),
        (Md5Utf16Be, Md5Pw),
        (Md5Dup, First16),
        (Md5Md5Rev, First16),
        (Md5HexFull, First16),
        (Md5HexLo16, First16),
        (Md5Dup, Zeros),
        (Md5Md5Rev, Zeros),
        (Md5HexFull, Zeros),
        (Md5HexLo16, Zeros),
        (Md5Dup, Md5Pw),
        (Md5Md5Rev, Md5Pw),
        (Md5HexFull, Md5Pw),
        (Md5HexLo16, Md5Pw),
    ]
    .into_iter()
    .map(|(k, v)| cfg(k, v))
    .collect()
}

/// Las 15 entries añadidas en Fase 3.5, en el orden documentado.
fn fase35_15() -> Vec<ConfigEntry> {
    use IvSource::*;
    use Kdf::*;
    [
        (EvpMd5Aes256Nosalt, First16),
        (EvpMd5Aes256Nosalt, Zeros),
        (EvpMd5Aes256Nosalt, Md5Pw),
        (EvpMd5Aes192Nosalt, First16),
        (EvpMd5Aes192Nosalt, Zeros),
        (EvpMd5Aes192Nosalt, Md5Pw),
        (Md5Trunc24, First16),
        (Md5Trunc24, Zeros),
        (Md5Trunc24, Md5Pw),
        (Md5Md5x2_24, First16),
        (Md5Md5x2_24, Zeros),
        (Md5Md5x2_24, Md5Pw),
        (Md5HexLo24, First16),
        (Md5HexLo24, Zeros),
        (Md5HexLo24, Md5Pw),
    ]
    .into_iter()
    .map(|(k, v)| cfg(k, v))
    .collect()
}

#[test]
fn test_default_plan_order_is_42_cbc_configs() {
    let mut expected = original_27();
    expected.extend(fase35_15());
    assert_eq!(expected.len(), 42);

    let got = default_plan_order();
    assert_eq!(got.len(), 42);
    assert_eq!(got, expected, "el orden del plan exhaustivo no coincide");
    for c in &got {
        assert_eq!(c.mode, Mode::Cbc);
    }
}

#[test]
fn test_first_27_are_strict_prefix_of_42() {
    // Contrato D-013: las 27 entries originales DEBEN ser prefijo estricto
    // del plan extendido. Esto preserva el orden de exploración para
    // sesiones reanudadas y la coherencia con los presets canonical/likely.
    let got = default_plan_order();
    let original = original_27();
    assert!(got.len() >= 27);
    for (i, expected) in original.iter().enumerate() {
        assert_eq!(
            &got[i], expected,
            "el plan extendido debe coincidir con las 27 originales en idx={i}"
        );
    }
}

#[test]
fn test_presets_are_strict_prefixes() {
    let full = default_plan_order();
    assert_eq!(Preset::Canonical.configs(), full[..4].to_vec());
    assert_eq!(Preset::Likely.configs(), full[..12].to_vec());
    assert_eq!(Preset::Exhaustive.configs(), full);
}

#[test]
fn test_klen_distribution_in_plan() {
    let got = default_plan_order();
    let count_klen = |target: usize| got.iter().filter(|c| c.key_len_bytes() == target).count();
    // 6 KDFs × 3 IVs = 18 entries de AES-128
    assert_eq!(count_klen(16), 18);
    // 4 KDFs × 3 IVs = 12 entries de AES-192
    assert_eq!(count_klen(24), 12);
    // 4 KDFs × 3 IVs = 12 entries de AES-256
    assert_eq!(count_klen(32), 12);
    assert_eq!(count_klen(16) + count_klen(24) + count_klen(32), 42);
}
