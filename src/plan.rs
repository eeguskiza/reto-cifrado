//! Plan de barrido tras D-029: **una única configuración**
//! (`md5hex_full / aes-256-ecb / pkcs7`).
//!
//! El plan ya no es una lista de configs: es un descriptor único con la
//! metadata necesaria para reanudar (sha256 del fichero, batch_size,
//! versión del programa). El campo `program_version` se sube a `0.2.0`
//! para hacer un corte de compatibilidad explícito con planes pre-D-029
//! (que tenían `entries`, `preset`, etc.). Cargar un plan legacy
//! produce error claro y se invita al usuario a `quattro-crack reset
//! --yes`.

use serde::{Deserialize, Serialize};

/// Descripción legible de la única configuración activa.
///
/// Tras D-035 (refactor a la construcción real cifraronline.com): la
/// clave es `password.encode() + null pad` (sin MD5 ni hexify), AES-128,
/// ECB, NULL padding sobre `plaintext + MD5(plaintext).hexdigest()` para
/// integrity check.
pub const SINGLE_PLAN_DESCRIPTION: &str = "passraw / aes-128-ecb / nullpad / md5verify";

/// Bumpa con cada cambio incompatible del formato del plan o del kernel.
/// Pre-D-029 era `0.1.0`; tras D-029 fue `0.2.0`; tras D-035 sube a
/// `1.0.0` (la construcción criptográfica cambió por completo, los
/// planes y states pre-D-035 son inservibles).
pub const PLAN_FORMAT_VERSION: &str = "1.0.0";

/// Plan persistible — lo que va a `state/plan.toml`.
///
/// Tras D-029 no hay enum `Preset` ni `entries`, el plan es siempre el
/// mismo. Los campos que se mantienen son los que dan información de
/// reanudación: versión, fichero objetivo, sha256, batch_size, modo de
/// recorrido.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    /// Versión del plan/binario que generó este fichero. Se compara al
    /// reanudar con `same_major()`.
    pub program_version: String,
    /// Path del fichero objetivo (informativo).
    pub source_path: String,
    /// SHA-256 hex del fichero objetivo. Si difiere al reanudar, se
    /// rechaza la sesión (D-007 — el ciphertext ha cambiado).
    pub source_sha256: String,
    /// Tamaño de batch del kernel. Default 64 Mi (D-025).
    pub batch_size: u32,
    /// Modo de recorrido del espacio. Solo `Linear` está implementado;
    /// el campo se mantiene para que `state/plan.toml` siga teniendo
    /// la forma esperada y la deuda LCG de Fase 1 quede documentada.
    pub shuffle: ShuffleMode,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ShuffleMode {
    Linear,
    Lcg { seed: u64, a: u64, c: u64 },
}

impl Plan {
    /// Construye el plan único de la sesión, anclado al fichero objetivo
    /// (vía sha256) y con el `batch_size` elegido.
    pub fn new_single(
        program_version: impl Into<String>,
        source_path: impl Into<String>,
        source_sha256_hex: impl Into<String>,
        batch_size: u32,
    ) -> Self {
        Self {
            program_version: program_version.into(),
            source_path: source_path.into(),
            source_sha256: source_sha256_hex.into(),
            batch_size,
            shuffle: ShuffleMode::Linear,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_is_stable_label() {
        assert!(SINGLE_PLAN_DESCRIPTION.contains("passraw"));
        assert!(SINGLE_PLAN_DESCRIPTION.contains("aes-128-ecb"));
        assert!(SINGLE_PLAN_DESCRIPTION.contains("nullpad"));
        assert!(SINGLE_PLAN_DESCRIPTION.contains("md5verify"));
    }

    #[test]
    fn plan_round_trips_via_toml() {
        let p = Plan::new_single(
            PLAN_FORMAT_VERSION,
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            64 * 1024 * 1024,
        );
        let s = toml::to_string_pretty(&p).unwrap();
        let q: Plan = toml::from_str(&s).unwrap();
        assert_eq!(p.batch_size, q.batch_size);
        assert_eq!(p.source_sha256, q.source_sha256);
        assert!(matches!(q.shuffle, ShuffleMode::Linear));
    }
}
