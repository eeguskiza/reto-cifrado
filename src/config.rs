//! Tipos de configuración del barrido.
//!
//! Tras el refactor D-029 (autor del reto confirmó AES-256-ECB + md5hex),
//! el barrido tiene **una única configuración** y no necesita enum de
//! modos, IVs, KDFs ni presets. Esos enum vivían aquí en Fase 2–6.
//!
//! Lo que queda en este módulo es un descriptor de marca (`SINGLE_CONFIG_ID`)
//! para logs y un re-export del enum `Kdf` legacy para los tests que aún
//! lo necesiten (no expuesto vía CLI).

/// Identificador legible de la única configuración activa post-D-029.
/// Aparece en logs, en la TUI y en `quattro-crack plan`.
pub const SINGLE_CONFIG_ID: &str = "md5hex_full / aes-256-ecb / pkcs7";

/// Re-export del enum de KDFs legacy. Solo sirve a los tests que validan
/// los 14 KDFs CPU↔Python — la CLI nunca lo expone (D-029).
pub use crate::kdf::legacy::Kdf;
