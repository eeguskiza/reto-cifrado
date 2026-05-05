//! Plan de barrido: 27 configuraciones (KDF × IV) ordenadas por
//! probabilidad descendente, agrupadas en tres presets canónicos.
//!
//! Ver `DECISIONS.md` D-008.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{ConfigEntry, IvSource, Kdf};

/// Selección preconstruida de subconjuntos del plan.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum Preset {
    /// Las 4 configuraciones más probables (~1,5 h estimadas).
    Canonical,
    /// Las 12 configuraciones probables (~5 h estimadas).
    Likely,
    /// Las 27 configuraciones, default (~10–15 h estimadas).
    Exhaustive,
}

impl Preset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Likely => "likely",
            Self::Exhaustive => "exhaustive",
        }
    }

    /// Cardinalidad del preset.
    pub fn config_count(self) -> usize {
        match self {
            Self::Canonical => 4,
            Self::Likely => 12,
            // Fase 3.5: 27 originales + 15 nuevas (5 KDFs × 3 IVs).
            Self::Exhaustive => 42,
        }
    }

    /// Configuraciones del preset, en orden.
    pub fn configs(self) -> Vec<ConfigEntry> {
        let all = default_plan_order();
        all.into_iter().take(self.config_count()).collect()
    }
}

/// Plan ordenado de 42 configuraciones, listadas por probabilidad
/// descendente.
///
/// **Estructura del orden**:
///
/// 1. **27 entries originales (Fase 3)**: producto de las 9 KDFs MD5
///    primarias × 3 IVs en el orden documentado en el prompt v3.
///    `tests/plan_order.rs::test_default_plan_order_is_42_cbc_configs`
///    verifica que estas 27 son **prefijo estricto** del plan completo.
/// 2. **15 entries Fase 3.5**: 5 KDFs nuevas × 3 IVs, ordenadas:
///    primero las EVP_BytesToKey (más probables académicamente),
///    después las KDFs de 24 B truncadas; cada KDF con sus tres IVs
///    (`first16`, `zeros`, `md5pw`) consecutivos.
///
/// **Importante**: este orden es contrato. Si lo cambias, actualiza
/// también `tests/plan_order.rs` y la documentación.
pub fn default_plan_order() -> Vec<ConfigEntry> {
    use IvSource::*;
    use Kdf::*;

    [
        // ==================== 27 ORIGINALES (FASE 3) ====================
        // 1–4: canonical
        (Md5Utf8, First16),
        (Md5Utf16Le, First16),
        (Md5Utf8, Zeros),
        (Md5Utf8, Md5Pw),
        // 5–12: likely
        (Md5x2Utf8, First16),
        (PwPadded, First16),
        (Md5Utf16Le, Zeros),
        (Md5Utf16Le, Md5Pw),
        (Md5x2Utf8, Zeros),
        (Md5x2Utf8, Md5Pw),
        (PwPadded, Zeros),
        (PwPadded, Md5Pw),
        // 13–27: tail (UTF-16-BE y los KDFs originales de 32 B)
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
        // ==================== 15 NUEVAS (FASE 3.5) ====================
        // 28–33: EVP_BytesToKey (más probables académicamente)
        (EvpMd5Aes256Nosalt, First16),
        (EvpMd5Aes256Nosalt, Zeros),
        (EvpMd5Aes256Nosalt, Md5Pw),
        (EvpMd5Aes192Nosalt, First16),
        (EvpMd5Aes192Nosalt, Zeros),
        (EvpMd5Aes192Nosalt, Md5Pw),
        // 34–42: KDFs truncadas a 24 B (AES-192 sin EVP)
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
    .map(|(kdf, iv)| ConfigEntry::new(kdf, iv))
    .collect()
}

/// Plan persistible: lo que va a `state/plan.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Versión del programa que generó el plan (semver).
    pub program_version: String,
    /// Path del fichero objetivo.
    pub source_path: String,
    /// SHA-256 hex del fichero objetivo (formato `7fbc0cf9…`).
    pub source_sha256: String,
    /// Preset elegido en la invocación inicial. Si fue custom, `None`.
    pub preset: Option<Preset>,
    /// Configuraciones efectivas, en el orden a barrer.
    pub entries: Vec<ConfigEntry>,
    /// Tamaño de batch del kernel.
    pub batch_size: u32,
    /// Modo de recorrido del espacio.
    pub shuffle: ShuffleMode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ShuffleMode {
    Linear,
    Lcg { seed: u64, a: u64, c: u64 },
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("preset {0:?} no produce ninguna configuración")]
    EmptyPreset(Preset),
}

impl Plan {
    pub fn from_preset(
        program_version: impl Into<String>,
        source_path: impl Into<String>,
        source_sha256_hex: impl Into<String>,
        preset: Preset,
        batch_size: u32,
    ) -> Result<Self, PlanError> {
        let entries = preset.configs();
        if entries.is_empty() {
            return Err(PlanError::EmptyPreset(preset));
        }
        Ok(Self {
            program_version: program_version.into(),
            source_path: source_path.into(),
            source_sha256: source_sha256_hex.into(),
            preset: Some(preset),
            entries,
            batch_size,
            shuffle: ShuffleMode::Linear,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mode;

    #[test]
    fn default_order_has_42_entries_all_cbc() {
        let p = default_plan_order();
        assert_eq!(p.len(), 42);
        for (i, c) in p.iter().enumerate() {
            assert_eq!(c.mode, Mode::Cbc, "entrada {i} debe ser CBC");
        }
    }

    #[test]
    fn presets_have_documented_lengths() {
        assert_eq!(Preset::Canonical.config_count(), 4);
        assert_eq!(Preset::Likely.config_count(), 12);
        assert_eq!(Preset::Exhaustive.config_count(), 42);
        assert_eq!(Preset::Canonical.configs().len(), 4);
        assert_eq!(Preset::Likely.configs().len(), 12);
        assert_eq!(Preset::Exhaustive.configs().len(), 42);
    }

    #[test]
    fn presets_are_prefixes_of_default_order() {
        let full = default_plan_order();
        for &preset in &[Preset::Canonical, Preset::Likely, Preset::Exhaustive] {
            let cfgs = preset.configs();
            for (i, c) in cfgs.iter().enumerate() {
                assert_eq!(*c, full[i], "preset={} idx={i}", preset.as_str());
            }
        }
    }

    #[test]
    fn unique_kdf_iv_combinations() {
        let p = default_plan_order();
        let mut seen = std::collections::HashSet::new();
        for c in &p {
            assert!(seen.insert((c.kdf, c.iv)), "duplicado: {}", c.display_id());
        }
        assert_eq!(seen.len(), 42);
    }

    #[test]
    fn covers_all_14_kdfs_with_3_ivs_each() {
        let p = default_plan_order();
        for &kdf in Kdf::all() {
            let count = p.iter().filter(|c| c.kdf == kdf).count();
            assert_eq!(count, 3, "kdf={} debe tener 3 IVs en el plan", kdf.as_str());
        }
        for &iv in &[IvSource::First16, IvSource::Zeros, IvSource::Md5Pw] {
            let count = p.iter().filter(|c| c.iv == iv).count();
            assert_eq!(count, 14, "iv={} debe tener 14 KDFs en el plan", iv.as_str());
        }
    }
}
