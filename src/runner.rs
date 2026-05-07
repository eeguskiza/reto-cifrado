//! Runner — orquesta el barrido CUDA con checkpointing y reanudación.
//!
//! Tras D-035 (refactor a la construcción real cifraronline.com), el
//! barrido sigue teniendo **una única configuración** pero ahora es
//! `passraw / aes-128-ecb / nullpad / md5verify`. El runner sigue
//! avanzando `progress.next_step` hasta `N` o hasta encontrar el hit;
//! la KDF en hot path desaparece (ya no hay MD5 ni hexify por
//! candidata) — la clave se construye trivialmente como
//! `password.encode() + null pad`.
//!
//! Contrato (heredado de Fase 4 + D-026):
//!
//! - **Granularidad de checkpoint**: persistencia atómica de
//!   `progress.toml` cada `flush_every_n_batches` batches.
//! - **Verificaciones al reanudar**: SHA-256 del fichero objetivo y
//!   `same_major(program_version)`. Si difieren, ABORTAR.
//! - **Validación de hits**: `validate_hit` (3 pasos: prefijo-16
//!   kernel, prefijo-32 LF/CRLF CPU, MD5 integrity check). MD5 fallido
//!   tras prefijo-32 OK → evento crítico (`Md5MismatchCritical`,
//!   equivalente al viejo `Pkcs7Mismatch` pre-D-035).
//! - **Apagado limpio**: stop flag entre batches.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{debug, error, info, warn};

use crate::ciphertext::Ciphertext;
use crate::combinatorics::{index_to_password, N};
use crate::cuda::{CudaCtx, KernelBundle};
use crate::plan::{Plan, SINGLE_PLAN_DESCRIPTION};
use crate::reference::{build_key_passraw, validate_hit, HitVerdict, LineEnding};
use crate::state::{
    load_plan, load_progress_with_bak, save_plan, save_progress_with_bak, Hit, Progress,
};

pub const PLAN_BASENAME: &str = "plan.toml";
pub const PROGRESS_BASENAME: &str = "progress.toml";

// ============================================================================
// ProgressSink trait + ProgressEvent enum
// ============================================================================

pub trait ProgressSink: Send + Sync {
    fn on_event(&self, event: ProgressEvent);
}

/// Eventos del runner. Tras D-035, `HitConfirmed` lleva el `LineEnding`
/// detectado (LF o CRLF) y el evento crítico se renombra a
/// `HitCriticalMd5Mismatch`.
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    PlanLoaded {
        total_candidates: u64,
        source_sha256: String,
        batch_size: u32,
        device_name: String,
        config_id: String,
    },
    Resumed {
        from_step: u64,
    },
    ResumeRejected {
        reason: String,
    },
    BatchCompleted {
        batch_num: u64,
        current_step: u64,
        candidates_in_batch: u64,
        batch_duration_ms: u64,
    },
    GpuSample {
        utilization_pct: u8,
        memory_used_mb: u64,
        memory_total_mb: u64,
        temperature_c: u8,
        power_w: u32,
    },
    GpuMetricsUnavailable {
        reason: String,
    },
    HitConfirmed {
        password: String,
        idx: u64,
        plaintext_hex_first_32: String,
        line_ending: LineEnding,
        elapsed_total: Duration,
    },
    HitDiscardedPrefixMismatch {
        idx: u64,
    },
    HitCriticalMd5Mismatch {
        idx: u64,
        password: String,
        line_ending: LineEnding,
        embedded_md5_hex: String,
        computed_md5_hex: String,
    },
    Paused {
        last_step: u64,
        elapsed_total: Duration,
    },
    PlanCompleted {
        total_hits: usize,
        elapsed_total: Duration,
    },
}

// ============================================================================
// StderrSink — formato Fase 4 simplificado tras D-029, adaptado D-035
// ============================================================================

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
        let mut w = match self.writer.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        match event {
            ProgressEvent::PlanLoaded {
                batch_size,
                device_name,
                config_id,
                ..
            } => {
                let _ = writeln!(
                    w,
                    "device: {device_name}\nplan: {config_id}, batch_size {batch_size}"
                );
            }
            ProgressEvent::BatchCompleted {
                batch_num,
                current_step,
                candidates_in_batch,
                batch_duration_ms,
            } => {
                if batch_num % 10 == 0 {
                    let pct = 100.0 * (current_step as f64) / (N as f64);
                    let ghs = if batch_duration_ms > 0 {
                        candidates_in_batch as f64 / (batch_duration_ms as f64 / 1000.0) / 1.0e9
                    } else {
                        0.0
                    };
                    let shown_idx = current_step.saturating_sub(candidates_in_batch);
                    let _ = writeln!(
                        w,
                        "  batch #{:>5} idx={:>15} ({:.4}% del espacio) {:.2} GH/s",
                        batch_num, shown_idx, pct, ghs
                    );
                }
            }
            ProgressEvent::HitConfirmed {
                password,
                idx,
                plaintext_hex_first_32,
                line_ending,
                elapsed_total,
            } => {
                let _ = writeln!(
                    w,
                    "================================================================"
                );
                let _ = writeln!(
                    w,
                    "  HIT CONFIRMADO  idx={}  pw='{}'  line_ending={}",
                    idx,
                    password,
                    line_ending.as_str()
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
            ProgressEvent::HitCriticalMd5Mismatch {
                idx,
                password,
                line_ending,
                embedded_md5_hex,
                computed_md5_hex,
            } => {
                let _ = writeln!(
                    w,
                    "================================================================"
                );
                let _ = writeln!(
                    w,
                    "CRITICAL: prefijo-32 ({}) OK pero MD5 INTEGRITY MISMATCH en idx={} pw='{}'",
                    line_ending.as_str(),
                    idx,
                    password
                );
                let _ = writeln!(w, "  embedded MD5(hex): {embedded_md5_hex}");
                let _ = writeln!(w, "  computed MD5(hex): {computed_md5_hex}");
                let _ = writeln!(
                    w,
                    "Probabilidad bajo AES real: ~2^-128 → casi seguro un BUG."
                );
                let _ = writeln!(w, "Posibles causas: kernel rota / construcción mal copiada / ciphertext corrupto.");
                let _ = writeln!(w, "ABORTANDO el barrido. Estado guardado para inspección.");
                let _ = writeln!(
                    w,
                    "================================================================"
                );
            }
            ProgressEvent::Paused {
                last_step,
                elapsed_total,
            } => {
                let _ = writeln!(
                    w,
                    "[pausa] elapsed={:.2}s; estado guardado en progress.toml. \
                     Reanuda con `quattro-crack run --resume`. last_step={}",
                    elapsed_total.as_secs_f64(),
                    last_step
                );
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
            ProgressEvent::Resumed { .. }
            | ProgressEvent::GpuSample { .. }
            | ProgressEvent::GpuMetricsUnavailable { .. }
            | ProgressEvent::HitDiscardedPrefixMismatch { .. } => {}
        }
        let _ = w.flush();
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
    pub resume: bool,
    pub force_resume: bool,
    pub flush_every_n_batches: u32,
}

#[derive(Debug, Clone)]
pub enum RunOutcome {
    Found { hit: Hit, elapsed_secs: f64 },
    Completed { elapsed_secs: f64 },
    Paused { elapsed_secs: f64, last_step: u64 },
}

pub fn run(opts: RunOptions, sink: &dyn ProgressSink, stop: Arc<AtomicBool>) -> Result<RunOutcome> {
    let plan_path = opts.state_dir.join(PLAN_BASENAME);
    let progress_path = opts.state_dir.join(PROGRESS_BASENAME);

    // ---------- 1. Cargar el ciphertext ----------
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
        let plan = Plan::new_single(
            crate::plan::PLAN_FORMAT_VERSION,
            ct.source_path.display().to_string(),
            sha_hex.clone(),
            opts.batch_size,
        );
        std::fs::create_dir_all(&opts.state_dir)?;
        save_plan(&plan_path, &plan)?;
        plan
    };

    // ---------- 3. Cargar/inicializar progreso ----------
    let mut progress = if opts.resume {
        match load_progress_with_bak(&progress_path) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "no hay progreso recuperable, arrancando limpio");
                Progress::new()
            }
        }
    } else {
        let _ = std::fs::remove_file(&progress_path);
        let _ = std::fs::remove_file(progress_bak_path(&progress_path));
        Progress::new()
    };

    // ---------- 4. Init CUDA ----------
    let cuda_ctx = CudaCtx::init().context("CUDA init")?;
    let device = cuda_ctx
        .device_name()
        .unwrap_or_else(|_| "<unknown>".into());

    sink.on_event(ProgressEvent::PlanLoaded {
        total_candidates: N,
        source_sha256: plan.source_sha256.clone(),
        batch_size: plan.batch_size,
        device_name: device.clone(),
        config_id: SINGLE_PLAN_DESCRIPTION.into(),
    });
    info!(
        device = %device,
        batch_size = plan.batch_size,
        config = SINGLE_PLAN_DESCRIPTION,
        "plan loaded"
    );

    if opts.resume {
        sink.on_event(ProgressEvent::Resumed {
            from_step: progress.next_step,
        });
    }

    // ---------- 5. Bucle principal ----------
    let started = Instant::now();
    let flush_every = opts.flush_every_n_batches.max(1) as u64;

    let mut bundle = KernelBundle::load(&cuda_ctx).context("KernelBundle::load")?;
    let ct_block_0: [u8; 16] = *ct.ct_first_block();
    let mut batches_run: u64 = 0;

    loop {
        if stop.load(Ordering::SeqCst) {
            progress.last_flush_utc = utc_now();
            save_progress_with_bak(&progress_path, &progress)?;
            let elapsed = started.elapsed();
            let last_step = progress.next_step;
            sink.on_event(ProgressEvent::Paused {
                last_step,
                elapsed_total: elapsed,
            });
            warn!(elapsed_s = elapsed.as_secs_f64(), last_step, "paused");
            return Ok(RunOutcome::Paused {
                elapsed_secs: elapsed.as_secs_f64(),
                last_step,
            });
        }

        let next_step = progress.next_step;
        if next_step >= N {
            break;
        }
        let idx_count = (plan.batch_size as u64).min(N - next_step);

        let batch_started = Instant::now();
        let device_hits = bundle
            .launch(next_step, idx_count, &ct_block_0)
            .with_context(|| format!("launch en idx_base {}", next_step))?;
        let batch_elapsed = batch_started.elapsed();

        progress.next_step = next_step + idx_count;
        progress.tried += idx_count;
        progress.elapsed_us += batch_elapsed.as_micros() as u64;
        batches_run += 1;

        // Validación CPU de cada hit reportado por el kernel (D-035).
        for dh in &device_hits {
            let pw_arr = index_to_password(dh.idx);
            let pw_utf8: &[u8] = &pw_arr;
            let key = build_key_passraw(pw_utf8);

            let verdict = validate_hit(&key, ct.ct()).context("validate_hit")?;
            match verdict {
                HitVerdict::Confirmed {
                    plaintext,
                    line_ending,
                } => {
                    let pw_str = std::str::from_utf8(pw_utf8)
                        .unwrap_or("<no utf8>")
                        .to_string();
                    let pt_hex = hex::encode(&plaintext);
                    let pt_first_32 = pt_hex.get(..64).unwrap_or(pt_hex.as_str()).to_string();
                    let hit = Hit {
                        idx: dh.idx,
                        password: pw_str.clone(),
                        plaintext_hex: pt_hex,
                        when_utc: utc_now(),
                    };
                    progress.hits.push(hit.clone());
                    progress.last_flush_utc = utc_now();
                    save_progress_with_bak(&progress_path, &progress)?;
                    let elapsed = started.elapsed();
                    sink.on_event(ProgressEvent::HitConfirmed {
                        password: pw_str.clone(),
                        idx: dh.idx,
                        plaintext_hex_first_32: pt_first_32,
                        line_ending,
                        elapsed_total: elapsed,
                    });
                    info!(
                        idx = dh.idx,
                        pw = %pw_str,
                        line_ending = line_ending.as_str(),
                        elapsed_s = elapsed.as_secs_f64(),
                        "HIT CONFIRMED"
                    );
                    return Ok(RunOutcome::Found {
                        hit,
                        elapsed_secs: elapsed.as_secs_f64(),
                    });
                }
                HitVerdict::Md5MismatchCritical {
                    embedded_md5_hex,
                    computed_md5_hex,
                    line_ending,
                    ..
                } => {
                    let pw_str = std::str::from_utf8(pw_utf8)
                        .unwrap_or("<no utf8>")
                        .to_string();
                    let emb_hex = String::from_utf8_lossy(&embedded_md5_hex).to_string();
                    let com_hex = String::from_utf8_lossy(&computed_md5_hex).to_string();
                    sink.on_event(ProgressEvent::HitCriticalMd5Mismatch {
                        idx: dh.idx,
                        password: pw_str.clone(),
                        line_ending,
                        embedded_md5_hex: emb_hex.clone(),
                        computed_md5_hex: com_hex.clone(),
                    });
                    error!(
                        idx = dh.idx,
                        pw = %pw_str,
                        line_ending = line_ending.as_str(),
                        embedded = %emb_hex,
                        computed = %com_hex,
                        "CRITICAL: prefijo-32 OK pero MD5 integrity mismatch"
                    );
                    progress.last_flush_utc = utc_now();
                    save_progress_with_bak(&progress_path, &progress)?;
                    return Err(anyhow!(
                        "Md5MismatchCritical evento crítico (idx={}) — ver D-035",
                        dh.idx
                    ));
                }
                HitVerdict::PrefixMismatch32 { plaintext_first_32 } => {
                    sink.on_event(ProgressEvent::HitDiscardedPrefixMismatch { idx: dh.idx });
                    let pw_str = std::str::from_utf8(pw_utf8)
                        .unwrap_or("<no utf8>")
                        .to_string();
                    info!(
                        idx = dh.idx,
                        password = %pw_str,
                        plaintext_first_32_hex = %hex::encode(plaintext_first_32),
                        "PREFIX32_MISMATCH descartado por validación CPU (D-034/D-035)"
                    );
                    progress.prefix32_mismatch_count =
                        progress.prefix32_mismatch_count.saturating_add(1);
                    if progress.prefix32_mismatch_idx_samples.len() < 16 {
                        progress.prefix32_mismatch_idx_samples.push(dh.idx);
                    }
                }
            }
        }

        // Persistencia agrupada (D-026).
        if batches_run % flush_every == 0 {
            progress.last_flush_utc = utc_now();
            save_progress_with_bak(&progress_path, &progress)?;
        }

        sink.on_event(ProgressEvent::BatchCompleted {
            batch_num: batches_run,
            current_step: progress.next_step,
            candidates_in_batch: idx_count,
            batch_duration_ms: batch_elapsed.as_millis() as u64,
        });
        if batches_run % 50 == 0 {
            debug!(
                batch = batches_run,
                next_step = progress.next_step,
                "batch completed"
            );
        }
    }

    // Plan completado sin hit. Flush final.
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
        prefix32_mismatches = progress.prefix32_mismatch_count,
        "plan completed without confirmed hit"
    );
    if progress.prefix32_mismatch_count > 0 {
        warn!(
            count = progress.prefix32_mismatch_count,
            samples = ?progress.prefix32_mismatch_idx_samples,
            "{} descartes por prefix32 mismatch durante el barrido. \
             Revisa state/progress.toml campo prefix32_mismatch_idx_samples \
             para diagnóstico. Esto NO debería ocurrir si la construcción \
             criptográfica es correcta — un descarte indica un bug \
             potencial en KNOWN_PREFIX_32_LF/CRLF (D-035) o en la KDF.",
            progress.prefix32_mismatch_count
        );
    }
    Ok(RunOutcome::Completed {
        elapsed_secs: elapsed.as_secs_f64(),
    })
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
