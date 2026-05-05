//! Persistencia atómica de estado de barrido.
//!
//! Modelo (§7.1 de la spec):
//!
//! - `plan.toml`   inmutable durante una sesión, generado al lanzar.
//! - `progress.toml` mutable, reescrito al final de cada batch (§7.2).
//!
//! Escritura atómica (§7.3):
//!
//! 1. serializar a memoria
//! 2. escribir a `<path>.new`
//! 3. `fsync(<path>.new)` y `fsync(<dir>)`
//! 4. `rename(<path>.new, <path>)` (atómico en POSIX)
//!
//! Recovery (§7.3, §7.4): si al cargar existe `<path>.new`, se elimina
//! (porque o el rename ya pasó y `.new` huérfano sobra, o el rename no
//! pasó y `.new` puede estar corrupto). Solo se considera autoritativo
//! `<path>` ya renombrado.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::ConfigEntry;
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
}

/// Hit confirmado encontrado durante el barrido.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Hit {
    /// Índice global dentro del campo de la configuración que lo encontró.
    pub idx: u64,
    /// Configuración que produjo el hit.
    pub config: ConfigEntry,
    /// Password recuperado, ASCII.
    pub password: String,
    /// Plaintext completo en hex, para auditoría.
    pub plaintext_hex: String,
    /// Timestamp ISO-8601 UTC del hit.
    pub when_utc: String,
}

/// Estado por configuración.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ConfigProgress {
    /// Siguiente paso `s` (0-indexado) NO probado todavía.
    /// `0` = no empezada. `N` = completada (donde N = cardinalidad del espacio).
    pub next_step: u64,
    /// Microsegundos de cómputo total acumulados (CPU+GPU).
    pub elapsed_us: u64,
    /// Candidatas probadas (puede ser igual a next_step si no hay LCG).
    pub tried: u64,
}

/// Estado mutable: lo que se reescribe al terminar cada batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Progress {
    /// Índice (en el plan) de la configuración actual.
    pub current_config: usize,
    /// Vector paralelo a `Plan::entries`: progreso por configuración.
    pub per_config: Vec<ConfigProgress>,
    /// Hits encontrados.
    pub hits: Vec<Hit>,
    /// Timestamp ISO-8601 UTC del último flush.
    pub last_flush_utc: String,
}

impl Progress {
    pub fn for_plan(plan: &Plan) -> Self {
        Self {
            current_config: 0,
            per_config: vec![ConfigProgress::default(); plan.entries.len()],
            hits: Vec::new(),
            last_flush_utc: String::new(),
        }
    }
}

// ----- I/O atómica genérica -----

/// Escribe `bytes` a `path` de forma atómica (write-tmp-fsync-rename).
///
/// Si el proceso muere entre cualquier paso intermedio, el `path` original
/// (si existía) queda intacto.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let parent = path.parent().ok_or_else(|| StateError::NoParent(path.into()))?;
    fs::create_dir_all(parent)?;

    let new_path = sidecar_new(path);

    // 1+2. Escribir a .new
    {
        let mut f: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&new_path)?;
        f.write_all(bytes)?;
        // 3. fsync del fichero
        f.sync_all()?;
    }

    // 4. rename atómico (POSIX, mismo FS)
    fs::rename(&new_path, path)?;

    // 5. fsync del directorio para asegurar que el rename está en disco.
    //    En algunos FS y plataformas (Windows) esto puede fallar; lo
    //    ignoramos en ese caso porque la atomicidad del rename ya está
    //    garantizada por el FS subyacente.
    if let Ok(dir) = OpenOptions::new().read(true).open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

/// Carga `path` aplicando la regla de recovery: si existe `path.new`, se
/// borra antes de leer (§7.3).
pub fn atomic_load(path: &Path) -> Result<Vec<u8>, StateError> {
    let new_path = sidecar_new(path);
    if new_path.exists() {
        // No usamos el .new como fuente: o el rename ya pasó y `.new`
        // sobra, o no pasó y puede estar corrupto. Se descarta.
        let _ = fs::remove_file(&new_path);
    }
    Ok(fs::read(path)?)
}

fn sidecar_new(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".new");
    PathBuf::from(s)
}

// ----- Helpers tipados para Plan / Progress -----

pub fn save_plan(path: &Path, plan: &Plan) -> Result<(), StateError> {
    let text = toml::to_string_pretty(plan)?;
    atomic_write(path, text.as_bytes())
}

pub fn load_plan(path: &Path) -> Result<Plan, StateError> {
    let bytes = atomic_load(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        StateError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("plan no es UTF-8: {e}"),
        ))
    })?;
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
    Ok(toml::from_str(text)?)
}

/// Path para el backup `<path>.bak`.
fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// Como `save_progress` pero rota el `<path>.toml` actual a `<path>.toml.bak`
/// antes de escribir el nuevo. Si el flush actual se corrompe (ej. corte
/// de luz post-fsync), `load_progress_with_bak` puede recuperar el flush
/// inmediatamente anterior.
pub fn save_progress_with_bak(path: &Path, progress: &Progress) -> Result<(), StateError> {
    if path.exists() {
        let bak = bak_path(path);
        // Mejor esfuerzo: si el copy falla (FS lleno, permisos), seguimos
        // con el flush principal. La pérdida del .bak es aceptable; la
        // pérdida del .toml no.
        let _ = fs::copy(path, &bak);
    }
    save_progress(path, progress)
}

/// Como `load_progress` pero, si el principal está corrupto o ausente,
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

    /// Simula el caso "muerte entre fsync y rename": existe `.new` con
    /// contenido nuevo, el original con el viejo, no hubo rename.
    /// La carga debe devolver el viejo intacto y limpiar el `.new`.
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

        let plan = Plan::from_preset(
            "0.1.0",
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            crate::plan::Preset::Canonical,
            16_777_216,
        )
        .unwrap();

        save_plan(&path, &plan).unwrap();
        let loaded = load_plan(&path).unwrap();
        assert_eq!(loaded.entries.len(), plan.entries.len());
        assert_eq!(loaded.entries, plan.entries);
        assert_eq!(loaded.batch_size, plan.batch_size);
        assert_eq!(loaded.preset, plan.preset);
    }

    #[test]
    fn save_progress_with_bak_rotates_previous_flush() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let bak = tmp.path().join("progress.toml.bak");

        let plan = Plan::from_preset(
            "0.1.0",
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            crate::plan::Preset::Canonical,
            16_777_216,
        )
        .unwrap();

        let mut p1 = Progress::for_plan(&plan);
        p1.per_config[0].next_step = 100;
        save_progress_with_bak(&path, &p1).unwrap();
        assert!(path.exists());
        assert!(!bak.exists(), "primer flush no debe crear .bak (no había nada que rotar)");

        let mut p2 = Progress::for_plan(&plan);
        p2.per_config[0].next_step = 200;
        save_progress_with_bak(&path, &p2).unwrap();
        assert!(path.exists());
        assert!(bak.exists(), "segundo flush DEBE haber rotado el primero a .bak");

        let main = load_progress(&path).unwrap();
        assert_eq!(main.per_config[0].next_step, 200);
        let bak_loaded = load_progress(&bak).unwrap();
        assert_eq!(bak_loaded.per_config[0].next_step, 100);
    }

    #[test]
    fn load_progress_with_bak_falls_back_when_main_corrupt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");
        let bak = tmp.path().join("progress.toml.bak");

        let plan = Plan::from_preset(
            "0.1.0",
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            crate::plan::Preset::Canonical,
            16_777_216,
        )
        .unwrap();
        let p = Progress::for_plan(&plan);
        save_progress(&bak, &p).unwrap();

        // .toml principal corrupto:
        fs::write(&path, b"esto no es toml valido =====").unwrap();

        let loaded = load_progress_with_bak(&path).expect("debe caer al .bak");
        assert_eq!(loaded.per_config.len(), p.per_config.len());
    }

    #[test]
    fn progress_round_trips_through_toml() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("progress.toml");

        let plan = Plan::from_preset(
            "0.1.0",
            "/tmp/cifrado.txt",
            "deadbeef".repeat(8),
            crate::plan::Preset::Canonical,
            16_777_216,
        )
        .unwrap();
        let mut progress = Progress::for_plan(&plan);
        progress.per_config[0].next_step = 12_345_678;
        progress.per_config[0].tried = 12_345_678;
        progress.last_flush_utc = "2026-05-05T20:30:00Z".into();

        save_progress(&path, &progress).unwrap();
        let loaded = load_progress(&path).unwrap();
        assert_eq!(loaded.per_config[0].next_step, 12_345_678);
        assert_eq!(loaded.last_flush_utc, "2026-05-05T20:30:00Z");
    }
}
