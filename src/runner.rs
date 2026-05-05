//! Runner — orquesta el barrido CUDA con checkpointing y reanudación.
//!
//! Contrato (spec §7):
//!
//! - **Granularidad de checkpoint**: persistencia atómica de
//!   `progress.toml` AL FINAL DE CADA BATCH del kernel (§7.2).
//! - **Verificaciones al reanudar** (§7.4):
//!   - SHA-256 de `cifrado.txt` debe coincidir con el del `plan.toml`;
//!     si difiere, ABORTAR.
//!   - Versión del programa: mismo major (relajable con `--force-resume`).
//!   - Si `progress.toml` está corrupto, caer a `progress.toml.bak`.
//! - **Validación de hits** (§7.4 + D-007):
//!   - Cuando el kernel emite un hit, descifrar 1600 B en CPU.
//!   - Validar prefijo-32 + PKCS7. Si pasa (1)+(2) pero falla PKCS7,
//!     evento crítico: ABORTAR el barrido.
//! - **Apagado limpio** (§7.5): el runner consulta el flag `stop` al
//!   final de cada batch; si está set, persiste y sale con
//!   `RunOutcome::Paused`.
//!
//! **Salida desacoplada (Fase 5)**: el runner no hace `eprintln!`;
//! emite `ProgressEvent` por un `ProgressSink`. Dos implementaciones:
//! `StderrSink` (replica el formato de Fase 4 línea a línea) y
//! `TuiSink` (en `src/tui.rs`, render con `indicatif`). Tracing va en
//! paralelo a fichero (configurado en `main.rs`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, error, info, warn};

use crate::ciphertext::Ciphertext;
use crate::combinatorics::{index_to_password, N};
use crate::config::{ConfigEntry, IvSource, Kdf};
use crate::cuda::{CudaCtx, KernelBundle};
use crate::kdf::derive;
use crate::plan::{Plan, Preset};
use crate::reference::{validate_hit, HitVerdict};
use crate::state::{
    load_plan, load_progress_with_bak, save_plan, save_progress_with_bak, Hit, Progress,
};

/// Path basenames bajo `state_dir`.
pub const PLAN_BASENAME: &str = "plan.toml";
pub const PROGRESS_BASENAME: &str = "progress.toml";

// ============================================================================
// ProgressSink trait + ProgressEvent enum
// ============================================================================

/// Sink al que el runner envía eventos. Las implementaciones concretas
/// (`StderrSink`, `TuiSink`) deciden cómo renderizarlos.
///
/// El método `on_event` recibe `&self` para que el sink pueda compartirse
/// (`Arc<dyn ProgressSink>`) entre el hilo del runner y, p. ej., el hilo
/// de muestreo NVML. El sink **nunca** debe bloquear: `try_send` o
/// `unbounded` por debajo, según corresponda. Si un evento se descarta
/// por backpressure, no es problema del runner.
pub trait ProgressSink: Send + Sync {
    fn on_event(&self, event: ProgressEvent);
}

/// Eventos del runner. Cubre cada punto donde Fase 4 hacía `eprintln!`,
/// más métricas externas (NVML) y eventos para diagnóstico.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Plan listo; runner a punto de empezar a iterar configs.
    PlanLoaded {
        total_configs: usize,
        total_candidates: u64,
        source_sha256: String,
        preset_name: Option<String>,
        batch_size: u32,
        device_name: String,
    },
    /// Reanudación: el plan estaba previamente cargado y partimos de
    /// `from_step` en `config_idx`.
    Resumed {
        config_idx: usize,
        from_step: u64,
    },
    /// Reanudación rechazada (sha256 distinto, versión incompatible, etc.).
    /// Se emite ANTES de devolver el `Err` correspondiente.
    ResumeRejected {
        reason: String,
    },
    /// El runner empieza a procesar la config `idx`.
    ConfigStarted {
        idx: usize,
        total: usize,
        kdf: String,
        iv: String,
        klen: usize,
        start_step: u64,
    },
    /// Un batch acaba de terminar. Persistencia atómica YA aplicada.
    BatchCompleted {
        config_idx: usize,
        batch_num: u64,
        current_step: u64,
        candidates_in_batch: u64,
        batch_duration_ms: u64,
    },
    /// Métrica NVML (sólo si la TUI lo pidió).
    GpuSample {
        utilization_pct: u8,
        memory_used_mb: u64,
        memory_total_mb: u64,
        temperature_c: u8,
        power_w: u32,
    },
    /// NVML no se pudo inicializar; el runner sigue funcionando.
    GpuMetricsUnavailable {
        reason: String,
    },
    /// Hit confirmado tras los 3 pasos (kernel + CPU + PKCS7).
    HitConfirmed {
        config_idx: usize,
        kdf: String,
        password: String,
        idx: u64,
        plaintext_hex_first_32: String,
        elapsed_total: Duration,
    },
    /// Falso positivo del kernel descartado en CPU (prefijo de 32 B falla).
    /// Esperado a ratio ~2⁻¹²⁸; útil para diagnóstico de tasa.
    HitDiscardedPrefixMismatch {
        config_idx: usize,
        idx: u64,
    },
    /// EVENTO CRÍTICO: prefijo de 32 B coincide pero PKCS7 falla.
    /// El runner ABORTA tras emitir esto.
    HitCriticalPkcs7Mismatch {
        config_idx: usize,
        idx: u64,
        password: String,
    },
    /// SIGINT/SIGTERM recibido y batch en curso terminado.
    Paused {
        config_idx: usize,
        last_step: u64,
        elapsed_total: Duration,
    },
    /// La config `idx` se completó (alcanzó N o estaba marcada como skip).
    ConfigCompleted {
        idx: usize,
        candidates_processed: u64,
        duration: Duration,
        hits: usize,
    },
    /// Plan completado: todas las configs barridas sin hit confirmado.
    PlanCompleted {
        total_hits: usize,
        elapsed_total: Duration,
    },
}

// ============================================================================
// StderrSink — replica formato de Fase 4 (los tests existentes lo dependen)
// ============================================================================

/// Sink que escribe a stderr con el formato exacto de Fase 4. Default
/// fallback cuando stdout no es TTY o cuando se pasa `--no-tui`.
///
/// Genérico sobre el writer para facilitar tests (vía `Arc<Mutex<Vec<u8>>>`).
pub struct StderrSink<W: Write + Send> {
    writer: Arc<Mutex<W>>,
}

impl StderrSink<std::io::Stderr> {
    pub fn new() -> Self {
        Self {
            writer: Arc::new(Mutex::new(std::io::stderr())),
        }
    }
}

impl Default for StderrSink<std::io::Stderr> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W: Write + Send> StderrSink<W> {
    pub fn from_writer(w: W) -> Self {
        Self {
            writer: Arc::new(Mutex::new(w)),
        }
    }
}

impl<W: Write + Send> ProgressSink for StderrSink<W>
where
    W: 'static,
{
    fn on_event(&self, event: ProgressEvent) {
        // Bloqueo del writer SOLO mientras formateamos. Con `eprintln!`
        // no había bloqueo explícito (lo gestiona stderr), así que aquí
        // mantenemos el comportamiento equivalente.
        let mut w = match self.writer.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match event {
            ProgressEvent::PlanLoaded {
                total_configs,
                preset_name,
                batch_size,
                device_name,
                ..
            } => {
                let preset_dbg = match preset_name {
                    Some(name) => format!("Some({})", capitalize(&name)),
                    None => "None".to_string(),
                };
                let _ = writeln!(
                    w,
                    "device: {device_name}\nplan: {total_configs} entries (preset {preset_dbg}), batch_size {batch_size}"
                );
            }
            ProgressEvent::ConfigStarted {
                idx,
                total,
                kdf,
                iv,
                klen,
                start_step,
            } => {
                let _ = writeln!(
                    w,
                    "[cfg {}/{}] {}/cbc/{} (klen {} B), arranca en idx {}",
                    idx + 1,
                    total,
                    kdf,
                    iv,
                    klen,
                    start_step
                );
            }
            ProgressEvent::BatchCompleted {
                config_idx,
                batch_num,
                current_step,
                candidates_in_batch,
                batch_duration_ms,
            } => {
                if batch_num % 10 == 0 {
                    let cfg_pct = 100.0 * (current_step as f64) / (N as f64);
                    let ghs = if batch_duration_ms > 0 {
                        candidates_in_batch as f64 / (batch_duration_ms as f64 / 1000.0) / 1.0e9
                    } else {
                        0.0
                    };
                    // Fase 4 usaba `next_step` ANTES del incremento como índice
                    // mostrado. Aquí `current_step` ya está incrementado, así
                    // que mostramos el inicio del batch terminado.
                    let shown_idx = current_step.saturating_sub(candidates_in_batch);
                    let _ = writeln!(
                        w,
                        "  cfg {}/?: batch #{:>5} idx={:>15} ({:.4}% del cfg) {:.2} GH/s",
                        config_idx + 1,
                        batch_num,
                        shown_idx,
                        cfg_pct,
                        ghs
                    );
                }
            }
            ProgressEvent::HitConfirmed {
                kdf,
                password,
                idx,
                plaintext_hex_first_32,
                elapsed_total,
                ..
            } => {
                let _ = writeln!(
                    w,
                    "================================================================"
                );
                let _ = writeln!(
                    w,
                    "  HIT CONFIRMADO  cfg={}/cbc/?  idx={}  pw='{}'",
                    kdf, idx, password
                );
                let _ = writeln!(
                    w,
                    "  elapsed={:.2}s   plaintext[..32]={}",
                    elapsed_total.as_secs_f64(),
                    plaintext_hex_first_32
                );
                let _ = writeln!(
                    w,
                    "================================================================"
                );
            }
            ProgressEvent::HitCriticalPkcs7Mismatch {
                config_idx,
                idx,
                password,
            } => {
                let _ = writeln!(
                    w,
                    "================================================================"
                );
                let _ = writeln!(
                    w,
                    "CRITICAL: prefijo-32 OK pero PKCS7 INVÁLIDO en idx={} cfg={} pw='{}'",
                    idx, config_idx, password
                );
                let _ = writeln!(w, "Probabilidad bajo CBC+PKCS7 real: ~2^-130 → casi seguro un BUG.");
                let _ = writeln!(w, "Posibles causas: KDF rota / kernel rota / ciphertext corrupto.");
                let _ = writeln!(w, "ABORTANDO el barrido. Estado guardado para inspección.");
                let _ = writeln!(
                    w,
                    "================================================================"
                );
            }
            ProgressEvent::Paused {
                last_step,
                elapsed_total,
                ..
            } => {
                let _ = writeln!(
                    w,
                    "[pausa] elapsed={:.2}s; estado guardado en progress.toml. \
                     Reanuda con `quattro-crack run --resume`. last_step={}",
                    elapsed_total.as_secs_f64(),
                    last_step
                );
            }
            ProgressEvent::ConfigCompleted { idx, .. } => {
                let _ = writeln!(w, "[cfg {}/?] completada", idx + 1);
            }
            ProgressEvent::PlanCompleted { elapsed_total, .. } => {
                let _ = writeln!(
                    w,
                    "plan completado SIN hit confirmado ({:.2}s)",
                    elapsed_total.as_secs_f64()
                );
            }
            ProgressEvent::ResumeRejected { reason } => {
                let _ = writeln!(w, "resume rechazado: {reason}");
            }
            // Eventos sólo informativos para la TUI; en stderr son ruido.
            ProgressEvent::Resumed { .. }
            | ProgressEvent::GpuSample { .. }
            | ProgressEvent::GpuMetricsUnavailable { .. }
            | ProgressEvent::HitDiscardedPrefixMismatch { .. } => {}
        }
        let _ = w.flush();
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(c).collect(),
    }
}

// ============================================================================
// run()
// ============================================================================

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub input_path: PathBuf,
    pub state_dir: PathBuf,
    pub batch_size: u32,
    pub preset: Preset,
    pub resume: bool,
    pub force_resume: bool,
    pub skip_configs: Vec<String>,
    pub only_configs: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// Hit confirmado encontrado.
    Found { hit: Hit, elapsed_secs: f64 },
    /// Plan recorrido completo sin hit.
    Completed { elapsed_secs: f64 },
    /// SIGINT/SIGTERM: estado guardado, salir con código 0.
    Paused {
        elapsed_secs: f64,
        last_config: usize,
        last_step: u64,
    },
}

pub fn run(
    opts: RunOptions,
    sink: &dyn ProgressSink,
    stop: Arc<AtomicBool>,
) -> Result<RunOutcome> {
    let plan_path = opts.state_dir.join(PLAN_BASENAME);
    let progress_path = opts.state_dir.join(PROGRESS_BASENAME);

    // ---------- 1. Cargar y validar el ciphertext ----------
    let ct = Ciphertext::load(&opts.input_path)
        .with_context(|| format!("cargando {}", opts.input_path.display()))?;
    let sha_hex = hex::encode(ct.source_sha256);

    // ---------- 2. Construir/cargar plan ----------
    let plan = if opts.resume {
        if !plan_path.exists() {
            let reason = format!(
                "no hay sesión previa para reanudar (no existe {}). \
                 Lanza sin --resume para crear un plan nuevo.",
                plan_path.display()
            );
            sink.on_event(ProgressEvent::ResumeRejected {
                reason: reason.clone(),
            });
            error!("{reason}");
            bail!(reason);
        }
        let plan =
            load_plan(&plan_path).with_context(|| format!("cargando {}", plan_path.display()))?;

        if plan.source_sha256 != sha_hex {
            let reason = format!(
                "el fichero objetivo ha cambiado desde la sesión guardada\n  \
                 esperado sha256: {}\n  \
                 actual sha256:   {}\n\
                 Lanza --reset para empezar de nuevo, o repón el fichero original.",
                plan.source_sha256, sha_hex
            );
            sink.on_event(ProgressEvent::ResumeRejected {
                reason: reason.clone(),
            });
            error!(expected = %plan.source_sha256, actual = %sha_hex, "resume rejected: sha256 mismatch");
            bail!(reason);
        }
        let curr = env!("CARGO_PKG_VERSION");
        if !opts.force_resume && !same_major(&plan.program_version, curr) {
            let reason = format!(
                "la versión guardada ({}) no es compatible con la actual ({}). \
                 Pasa --force-resume si confías en la migración.",
                plan.program_version, curr
            );
            sink.on_event(ProgressEvent::ResumeRejected {
                reason: reason.clone(),
            });
            error!(saved = %plan.program_version, current = %curr, "resume rejected: version mismatch");
            bail!(reason);
        }
        plan
    } else {
        let plan = Plan::from_preset(
            env!("CARGO_PKG_VERSION"),
            ct.source_path.display().to_string(),
            sha_hex.clone(),
            opts.preset,
            opts.batch_size,
        )?;
        std::fs::create_dir_all(&opts.state_dir)?;
        save_plan(&plan_path, &plan)?;
        plan
    };

    // ---------- 3. Cargar/inicializar progreso ----------
    let mut progress = if opts.resume {
        match load_progress_with_bak(&progress_path) {
            Ok(p) => {
                if p.per_config.len() != plan.entries.len() {
                    warn!(
                        loaded = p.per_config.len(),
                        expected = plan.entries.len(),
                        "per_config mismatch, reseteando progreso"
                    );
                    Progress::for_plan(&plan)
                } else {
                    p
                }
            }
            Err(e) => {
                warn!(error = %e, "no hay progreso recuperable, arrancando limpio");
                Progress::for_plan(&plan)
            }
        }
    } else {
        let _ = std::fs::remove_file(&progress_path);
        let _ = std::fs::remove_file(progress_bak_path(&progress_path));
        Progress::for_plan(&plan)
    };

    // ---------- 4. Aplicar skip/only ----------
    apply_skip_only(
        &mut progress,
        &plan.entries,
        &opts.skip_configs,
        &opts.only_configs,
    )?;

    // ---------- 5. Init CUDA ----------
    let cuda_ctx = CudaCtx::init().context("CUDA init")?;
    let device = cuda_ctx
        .device_name()
        .unwrap_or_else(|_| "<unknown>".into());

    sink.on_event(ProgressEvent::PlanLoaded {
        total_configs: plan.entries.len(),
        total_candidates: N,
        source_sha256: plan.source_sha256.clone(),
        preset_name: plan.preset.map(|p| p.as_str().to_string()),
        batch_size: plan.batch_size,
        device_name: device.clone(),
    });
    info!(
        configs = plan.entries.len(),
        device = %device,
        batch_size = plan.batch_size,
        "plan loaded"
    );

    if opts.resume {
        sink.on_event(ProgressEvent::Resumed {
            config_idx: progress.current_config,
            from_step: progress
                .per_config
                .get(progress.current_config)
                .map(|p| p.next_step)
                .unwrap_or(0),
        });
    }

    // ---------- 6. Bucle principal ----------
    let started = Instant::now();
    let total_configs = plan.entries.len();

    for cfg_idx in 0..total_configs {
        let cfg: ConfigEntry = plan.entries[cfg_idx];
        if progress.per_config[cfg_idx].next_step >= N {
            // Ya completada (o marcada por skip/only).
            sink.on_event(ProgressEvent::ConfigCompleted {
                idx: cfg_idx,
                candidates_processed: progress.per_config[cfg_idx].tried,
                duration: Duration::from_micros(progress.per_config[cfg_idx].elapsed_us),
                hits: 0,
            });
            continue;
        }
        progress.current_config = cfg_idx;

        let cfg_started_at = Instant::now();
        let start_idx = progress.per_config[cfg_idx].next_step;

        sink.on_event(ProgressEvent::ConfigStarted {
            idx: cfg_idx,
            total: total_configs,
            kdf: cfg.kdf.as_str().to_string(),
            iv: cfg.iv.as_str().to_string(),
            klen: cfg.key_len_bytes(),
            start_step: start_idx,
        });
        info!(
            idx = cfg_idx,
            cfg = %cfg.display_id(),
            klen = cfg.key_len_bytes(),
            start = start_idx,
            "config started"
        );

        let mut bundle = KernelBundle::load(&cuda_ctx, cfg.kdf)
            .with_context(|| format!("KernelBundle::load({})", cfg.kdf.as_str()))?;

        let iv_bytes: [u8; 16] = match cfg.iv {
            IvSource::First16 => *ct.iv(),
            IvSource::Zeros => [0u8; 16],
            IvSource::Md5Pw => [0u8; 16], // ignorado por el kernel
        };
        let ct_block_0: [u8; 16] = *ct.ct_first_block();
        let mut batches_run: u64 = 0;
        let cfg_hits_at_start = progress.hits.len();

        loop {
            // Stop flag — se respeta entre batches, no a media GPU.
            if stop.load(Ordering::SeqCst) {
                progress.last_flush_utc = utc_now();
                save_progress_with_bak(&progress_path, &progress)?;
                let elapsed = started.elapsed();
                let last_step = progress.per_config[cfg_idx].next_step;
                sink.on_event(ProgressEvent::Paused {
                    config_idx: cfg_idx,
                    last_step,
                    elapsed_total: elapsed,
                });
                warn!(elapsed_s = elapsed.as_secs_f64(), last_step, "paused");
                return Ok(RunOutcome::Paused {
                    elapsed_secs: elapsed.as_secs_f64(),
                    last_config: cfg_idx,
                    last_step,
                });
            }

            let next_step = progress.per_config[cfg_idx].next_step;
            if next_step >= N {
                break;
            }
            let idx_count = (plan.batch_size as u64).min(N - next_step);

            let batch_started = Instant::now();
            let device_hits = bundle
                .launch(next_step, idx_count, &iv_bytes, cfg.iv, &ct_block_0)
                .with_context(|| {
                    format!(
                        "launch en cfg {} ({}), idx_base {}",
                        cfg_idx,
                        cfg.display_id(),
                        next_step
                    )
                })?;
            let batch_elapsed = batch_started.elapsed();

            progress.per_config[cfg_idx].next_step = next_step + idx_count;
            progress.per_config[cfg_idx].tried += idx_count;
            progress.per_config[cfg_idx].elapsed_us += batch_elapsed.as_micros() as u64;
            batches_run += 1;

            // Validación CPU de cada hit reportado por el kernel.
            for dh in &device_hits {
                let pw_arr = index_to_password(dh.idx);
                let pw_utf8: &[u8] = &pw_arr;
                let key = derive(cfg.kdf, pw_utf8);

                let iv_for_validation: [u8; 16] = match cfg.iv {
                    IvSource::Md5Pw => {
                        let m = derive(Kdf::Md5Utf8, pw_utf8);
                        let mut iv = [0u8; 16];
                        iv.copy_from_slice(m.as_slice());
                        iv
                    }
                    _ => iv_bytes,
                };

                let verdict = validate_hit(key.as_slice(), &iv_for_validation, ct.ct())
                    .context("validate_hit")?;
                match verdict {
                    HitVerdict::Confirmed { plaintext } => {
                        let pw_str = std::str::from_utf8(pw_utf8)
                            .unwrap_or("<no utf8>")
                            .to_string();
                        let pt_hex = hex::encode(&plaintext);
                        let pt_first_32 = pt_hex
                            .get(..64)
                            .unwrap_or(pt_hex.as_str())
                            .to_string();
                        let hit = Hit {
                            idx: dh.idx,
                            config: cfg,
                            password: pw_str.clone(),
                            plaintext_hex: pt_hex,
                            when_utc: utc_now(),
                        };
                        progress.hits.push(hit.clone());
                        progress.last_flush_utc = utc_now();
                        save_progress_with_bak(&progress_path, &progress)?;
                        let elapsed = started.elapsed();
                        sink.on_event(ProgressEvent::HitConfirmed {
                            config_idx: cfg_idx,
                            kdf: cfg.kdf.as_str().to_string(),
                            password: pw_str.clone(),
                            idx: dh.idx,
                            plaintext_hex_first_32: pt_first_32,
                            elapsed_total: elapsed,
                        });
                        info!(
                            cfg = %cfg.display_id(),
                            idx = dh.idx,
                            pw = %pw_str,
                            elapsed_s = elapsed.as_secs_f64(),
                            "HIT CONFIRMED"
                        );
                        return Ok(RunOutcome::Found {
                            hit,
                            elapsed_secs: elapsed.as_secs_f64(),
                        });
                    }
                    HitVerdict::Pkcs7Mismatch { .. } => {
                        let pw_str = std::str::from_utf8(pw_utf8)
                            .unwrap_or("<no utf8>")
                            .to_string();
                        sink.on_event(ProgressEvent::HitCriticalPkcs7Mismatch {
                            config_idx: cfg_idx,
                            idx: dh.idx,
                            password: pw_str.clone(),
                        });
                        error!(
                            cfg = %cfg.display_id(),
                            idx = dh.idx,
                            pw = %pw_str,
                            "CRITICAL: prefijo-32 OK pero PKCS7 inválido"
                        );
                        progress.last_flush_utc = utc_now();
                        save_progress_with_bak(&progress_path, &progress)?;
                        return Err(anyhow!(
                            "Pkcs7Mismatch evento crítico (idx={}, cfg={}) — ver D-007",
                            dh.idx,
                            cfg.display_id()
                        ));
                    }
                    HitVerdict::PrefixMismatch32 => {
                        sink.on_event(ProgressEvent::HitDiscardedPrefixMismatch {
                            config_idx: cfg_idx,
                            idx: dh.idx,
                        });
                        debug!(idx = dh.idx, "kernel false positive (prefix32 mismatch)");
                    }
                }
            }

            // Persistencia atómica al final de cada batch (§7.2).
            progress.last_flush_utc = utc_now();
            save_progress_with_bak(&progress_path, &progress)?;

            sink.on_event(ProgressEvent::BatchCompleted {
                config_idx: cfg_idx,
                batch_num: batches_run,
                current_step: progress.per_config[cfg_idx].next_step,
                candidates_in_batch: idx_count,
                batch_duration_ms: batch_elapsed.as_millis() as u64,
            });
            if batches_run % 50 == 0 {
                debug!(
                    cfg = cfg_idx,
                    batch = batches_run,
                    next_step = progress.per_config[cfg_idx].next_step,
                    "batch completed"
                );
            }
        }

        let cfg_duration = cfg_started_at.elapsed();
        let cfg_hits = progress.hits.len() - cfg_hits_at_start;
        sink.on_event(ProgressEvent::ConfigCompleted {
            idx: cfg_idx,
            candidates_processed: progress.per_config[cfg_idx].tried,
            duration: cfg_duration,
            hits: cfg_hits,
        });
        info!(idx = cfg_idx, hits = cfg_hits, "config completed");
    }

    // Plan completado sin hit.
    progress.last_flush_utc = utc_now();
    save_progress_with_bak(&progress_path, &progress)?;
    let elapsed = started.elapsed();
    sink.on_event(ProgressEvent::PlanCompleted {
        total_hits: progress.hits.len(),
        elapsed_total: elapsed,
    });
    info!(
        elapsed_s = elapsed.as_secs_f64(),
        hits = progress.hits.len(),
        "plan completed without confirmed hit"
    );
    Ok(RunOutcome::Completed {
        elapsed_secs: elapsed.as_secs_f64(),
    })
}

fn apply_skip_only(
    progress: &mut Progress,
    entries: &[ConfigEntry],
    skip: &[String],
    only: &[String],
) -> Result<()> {
    if !only.is_empty() {
        for id in only {
            if !entries.iter().any(|e| &e.display_id() == id) {
                bail!("--only-config {id:?} no coincide con ninguna entry del plan");
            }
        }
        for (i, e) in entries.iter().enumerate() {
            let id = e.display_id();
            if !only.iter().any(|s| s == &id) {
                progress.per_config[i].next_step = N;
            }
        }
    }
    for id in skip {
        if let Some(i) = entries.iter().position(|e| &e.display_id() == id) {
            progress.per_config[i].next_step = N;
        } else {
            bail!("--skip-config {id:?} no coincide con ninguna entry del plan");
        }
    }
    Ok(())
}

fn same_major(a: &str, b: &str) -> bool {
    a.split('.').next() == b.split('.').next()
}

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn progress_bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}
