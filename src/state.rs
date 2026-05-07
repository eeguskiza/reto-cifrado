//! Persistencia atómica del estado de barrido.
//!
//! Tras D-029, el plan tiene una única configuración, así que `Progress`
//! deja de ser un vector paralelo a `entries` y pasa a ser un escalar:
//! un único `next_step` y un contador de `tried` y `elapsed_us`.
//!
//! El campo `Hit` también se simplifica: ya no incluye `ConfigEntry`
//! porque el contexto es implícito (única config).
//!
//! Se mantiene la atomicidad de Fase 4 (`atomic_write` con secuencia
//! tmp → fsync → rename → dir-fsync) y la rotación a `.bak` por
//! `save_progress_with_bak` (con `rename` en lugar de `copy`, D-026).
//!
//! Se añade `LegacyDetected`: si al cargar `progress.toml` se detecta
//! formato pre-D-029 (con `per_config`, `current_config`, etc.), se
//! devuelve un error claro pidiendo `quattro-crack reset --yes`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plan::Plan;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml serialize: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml deserialize: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("path no tiene parent dir: {0}")]
    NoParent(PathBuf),
    #[error(
        "{path} pertenece a una versión incompatible (pre-D-029, formato \
         multi-config). Lánzalo con `quattro-crack reset --yes` para empezar \
         de cero, o renombra/copia el fichero si quieres conservarlo."
    )]
    LegacyFormat { path: PathBuf },
}

/// Hit confirmado encontrado durante el barrido.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Hit {
    /// Índice global dentro del espacio combinatorio.
    pub idx: u64,
    /// Password recuperado, ASCII.
    pub password: String,
    /// Plaintext completo en hex, para auditoría.
    pub plaintext_hex: String,
    /// Timestamp ISO-8601 UTC del hit.
    pub when_utc: String,
}

/// Estado mutable: lo que se reescribe cada `flush_every` batches.
///
/// Forma post-D-029: un único `next_step` (índice 0..N a probar a
/// continuación), `tried` (candidatas barridas) y `elapsed_us`
/// (microsegundos GPU acumulados).
///
/// Tras D-034 se añaden contadores de descartes `PrefixMismatch32` para
/// que sean inspeccionables post-mortem aunque el proceso se cierre.
/// Los campos viejos sin estas claves se cargan con default vía
/// `#[serde(default)]`, preservando la compatibilidad de carga del
/// `progress.toml` existente.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Progress {
    /// Siguiente paso a probar. `0` = no empezada. `N` = completada.
    pub next_step: u64,
    /// Candidatas barridas hasta ahora.
    pub tried: u64,
    /// Microsegundos GPU acumulados (suma de tiempos de batch).
    pub elapsed_us: u64,
    /// Hits encontrados (normalmente 1 al terminar).
    pub hits: Vec<Hit>,
    /// Timestamp ISO-8601 UTC del último flush.
    pub last_flush_utc: String,
    /// Cuántos hits de kernel se descartaron por `PrefixMismatch32` (D-034).
    #[serde(default)]
    pub prefix32_mismatch_count: u64,
    /// Primeros 16 idx donde ocurrió un `PrefixMismatch32`, para diagnóstico.
    #[serde(default)]
    pub prefix32_mismatch_idx_samples: Vec<u64>,
}

impl Progress {
    /// Estado inicial vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compatibilidad con la API de Fase 4: arrancar un Progress
    /// asociado a un Plan. Hoy el plan no aporta forma al progress
    /// (es un escalar), así que ignoramos el parámetro.
    pub fn for_plan(_plan: &Plan) -> Self {
        Self::new()
    }
}

// ============================================================================
// I/O atómica genérica
// ============================================================================

/// Escribe `bytes` a `path` de forma atómica (write-tmp-fsync-rename).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::NoParent(path.into()))?;
    fs::create_dir_all(parent)?;

    let new_path = sidecar_new(path);

    {
        let mut f: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&new_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    fs::rename(&new_path, path)?;

    if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Carga `path` aplicando la regla de recovery: si existe `path.new`,
/// se borra antes de leer.
pub fn atomic_load(path: &Path) -> Result<Vec<u8>, StateError> {
    let new_path = sidecar_new(path);
    if new_path.exists() {
        let _ = fs::remove_file(&new_path);
    }
    Ok(fs::read(path)?)
}

fn sidecar_new(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

// ============================================================================
// Helpers tipados para Plan / Progress
// ============================================================================

pub fn save_plan(path: &Path, plan: &Plan) -> Result<(), StateError> {
    let text = toml::to_string_pretty(plan)?;
    atomic_write(path, text.as_bytes())
}

/// Carga `Plan` con detección de formato legacy. Si el TOML contiene
/// claves que solo existían pre-D-029 (`entries`, `preset`), devuelve
/// `StateError::LegacyFormat`.
pub fn load_plan(path: &Path) -> Result<Plan, StateError> {
    let bytes = atomic_load(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        StateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("plan no es UTF-8: {e}"),
        ))
    })?;
    if looks_like_legacy_plan(text) {
        return Err(StateError::LegacyFormat {
            path: path.to_path_buf(),
        });
    }
    Ok(toml::from_str(text)?)
}

pub fn save_progress(path: &Path, progress: &Progress) -> Result<(), StateError> {
    let text = toml::to_string_pretty(progress)?;
    atomic_write(path, text.as_bytes())
}

pub fn load_progress(path: &Path) -> Result<Progress, StateError> {
    let bytes = atomic_load(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        StateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("progress no es UTF-8: {e}"),
        ))
    })?;
    if looks_like_legacy_progress(text) {
        return Err(StateError::LegacyFormat {
            path: path.to_path_buf(),
        });
    }
    Ok(toml::from_str(text)?)
}

/// Detecta plan TOML pre-D-029: contiene `entries` o `preset`.
fn looks_like_legacy_plan(toml_text: &str) -> bool {
    toml_text.contains("[[entries]]")
        || toml_text.contains("\nentries =")
        || toml_text.contains("\npreset = ")
        || toml_text.contains("\npreset=\"")
}

/// Detecta progress TOML pre-D-029: contiene `per_config` o
/// `current_config`.
fn looks_like_legacy_progress(toml_text: &str) -> bool {
    toml_text.contains("[[per_config]]")
        || toml_text.contains("\nper_config =")
        || toml_text.contains("\ncurrent_config =")
}

fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// Como `save_progress` pero rota el actual a `.bak` antes de escribir
/// (D-026: usa `rename` en lugar de `copy`).
pub fn save_progress_with_bak(path: &Path, progress: &Progress) -> Result<(), StateError> {
    if path.exists() {
        let bak = bak_path(path);
        let _ = fs::rename(path, &bak);
    }
    save_progress(path, progress)
}

/// Como `load_progress` pero, si el principal está corrupto/ausente,
/// intenta `<path>.bak`.
pub fn load_progress_with_bak(path: &Path) -> Result<Progress, StateError> {
    match load_progress(path) {
        Ok(p) => Ok(p),
        Err(primary_err) => {
            let bak = bak_path(path);
            if bak.exists() {
                eprintln!(
                    "warning: {} corrupto/ausente ({primary_err}); cargando {}",
                    path.display(),
                    bak.display()
                );
                load_progress(&bak)
            } else {
                Err(primary_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_atomic_write() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.toml");
        atomic_write(&path, b"hola atomica").unwrap();
        assert_eq!(atomic_load(&path).unwrap(), b"hola atomica");
    }

    #[test]
    fn atomic_write_replaces_old_content() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.toml");
        atomic_write(&path, b"v1").unwrap();
        atomic_write(&path, b"v2").unwrap();
        assert_eq!(atomic_load(&path).unwrap(), b"v2");
    }

    #[test]
    fn atomic_load_discards_new_sidecar_when_present() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("state.toml");
        let new_path = tmp.path().join("state.toml.new");
        fs::write(&path, b"viejo bueno").unwrap();
        fs::write(&new_path, b"nuevo posible-corrupto").unwrap();
        let loaded = atomic_load(&path).unwrap();
        assert_eq!(loaded, b"viejo bueno");
        assert!(!new_path.exists(), ".new debería haberse limpiado");
    }

    #[test]
    fn plan_round_trips_through_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.toml");
        let plan = Plan::new_single(
            crate::plan::PLAN_FORMAT_VERSION,
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            64 * 1024 * 1024,
        );
        save_plan(&path, &plan).unwrap();
        let loaded = load_plan(&path).unwrap();
        assert_eq!(loaded.batch_size, plan.batch_size);
        assert_eq!(loaded.source_sha256, plan.source_sha256);
    }

    #[test]
    fn save_progress_with_bak_rotates_previous_flush() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let bak = tmp.path().join("progress.toml.bak");

        let mut p1 = Progress::new();
        p1.next_step = 100;
        save_progress_with_bak(&path, &p1).unwrap();
        assert!(path.exists());
        assert!(!bak.exists(), "primer flush no debe crear .bak");

        let mut p2 = Progress::new();
        p2.next_step = 200;
        save_progress_with_bak(&path, &p2).unwrap();
        assert!(path.exists());
        assert!(
            bak.exists(),
            "segundo flush DEBE haber rotado el primero a .bak"
        );

        let main = load_progress(&path).unwrap();
        assert_eq!(main.next_step, 200);
        let bak_loaded = load_progress(&bak).unwrap();
        assert_eq!(bak_loaded.next_step, 100);
    }

    #[test]
    fn load_progress_with_bak_falls_back_when_main_corrupt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let bak = tmp.path().join("progress.toml.bak");
        let mut p = Progress::new();
        p.next_step = 42;
        save_progress(&bak, &p).unwrap();
        fs::write(&path, b"esto no es toml valido =====").unwrap();
        let loaded = load_progress_with_bak(&path).expect("debe caer al .bak");
        assert_eq!(loaded.next_step, 42);
    }

    #[test]
    fn legacy_plan_format_is_rejected_with_clear_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("plan.toml");
        let legacy = r#"
program_version = "0.1.0"
source_path = "./data/cifrado.txt"
source_sha256 = "deadbeef"
preset = "Exhaustive"
batch_size = 16777216

[[entries]]
kdf = "Md5Utf8"
mode = "Cbc"
iv = "First16"
"#;
        fs::write(&path, legacy).unwrap();
        let err = load_plan(&path).expect_err("plan legacy debe fallar");
        assert!(matches!(err, StateError::LegacyFormat { .. }));
    }

    #[test]
    fn legacy_progress_format_is_rejected_with_clear_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let legacy = r#"
current_config = 0
hits = []
last_flush_utc = "2026-05-06T16:00:37Z"

[[per_config]]
next_step = 30000000000000
elapsed_us = 16000000000
tried = 30000000000000
"#;
        fs::write(&path, legacy).unwrap();
        let err = load_progress(&path).expect_err("progress legacy debe fallar");
        assert!(matches!(err, StateError::LegacyFormat { .. }));
    }

    #[test]
    fn progress_round_trips_through_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let mut progress = Progress::new();
        progress.next_step = 12_345_678;
        progress.tried = 12_345_678;
        progress.elapsed_us = 4_321_000;
        progress.last_flush_utc = "2026-05-06T20:30:00Z".into();
        save_progress(&path, &progress).unwrap();
        let loaded = load_progress(&path).unwrap();
        assert_eq!(loaded.next_step, 12_345_678);
        assert_eq!(loaded.last_flush_utc, "2026-05-06T20:30:00Z");
    }
}
