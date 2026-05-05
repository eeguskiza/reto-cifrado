//! `test_default_plan_order_is_27_cbc_configs` — el plan exhaustivo tiene
//! exactamente 27 entradas en el orden documentado en el prompt v3.

use quattro_crack::config::{ConfigEntry, IvSource, Kdf, Mode};
use quattro_crack::plan::{default_plan_order, Preset};

fn cfg(kdf: Kdf, iv: IvSource) -> ConfigEntry {
    ConfigEntry::new(kdf, iv)
}

#[test]
fn test_default_plan_order_is_27_cbc_configs() {
    use IvSource::*;
    use Kdf::*;

    let expected: Vec<ConfigEntry> = [
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
    .collect();

    let got = default_plan_order();
    assert_eq!(got.len(), 27);
    assert_eq!(got, expected, "el orden del plan exhaustivo no coincide");
    for c in &got {
        assert_eq!(c.mode, Mode::Cbc);
    }
}

#[test]
fn test_presets_are_strict_prefixes() {
    let full = default_plan_order();
    assert_eq!(Preset::Canonical.configs(), full[..4].to_vec());
    assert_eq!(Preset::Likely.configs(), full[..12].to_vec());
    assert_eq!(Preset::Exhaustive.configs(), full);
}
