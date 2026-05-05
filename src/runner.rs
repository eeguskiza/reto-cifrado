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
//! No hay TUI (Fase 5). Logs simples a `stderr`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};

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

pub fn run(opts: RunOptions, stop: Arc<AtomicBool>) -> Result<RunOutcome> {
    let plan_path = opts.state_dir.join(PLAN_BASENAME);
    let progress_path = opts.state_dir.join(PROGRESS_BASENAME);

    // ---------- 1. Cargar y validar el ciphertext ----------
    let ct = Ciphertext::load(&opts.input_path)
        .with_context(|| format!("cargando {}", opts.input_path.display()))?;
    let sha_hex = hex::encode(ct.source_sha256);

    // ---------- 2. Construir/cargar plan ----------
    let plan = if opts.resume {
        if !plan_path.exists() {
            bail!(
                "no hay sesión previa para reanudar (no existe {}). \
                 Lanza sin --resume para crear un plan nuevo.",
                plan_path.display()
            );
        }
        let plan =
            load_plan(&plan_path).with_context(|| format!("cargando {}", plan_path.display()))?;

        if plan.source_sha256 != sha_hex {
            bail!(
                "el fichero objetivo ha cambiado desde la sesión guardada\n  \
                 esperado sha256: {}\n  \
                 actual sha256:   {}\n\
                 Lanza --reset para empezar de nuevo, o repón el fichero original.",
                plan.source_sha256,
                sha_hex
            );
        }
        let curr = env!("CARGO_PKG_VERSION");
        if !opts.force_resume && !same_major(&plan.program_version, curr) {
            bail!(
                "la versión guardada ({}) no es compatible con la actual ({}). \
                 Pasa --force-resume si confías en la migración.",
                plan.program_version,
                curr
            );
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
                // Sanity: longitud del vector debe coincidir con plan.
                if p.per_config.len() != plan.entries.len() {
                    eprintln!(
                        "warning: per_config tenía {} entries pero plan tiene {}; reseteando progreso",
                        p.per_config.len(),
                        plan.entries.len()
                    );
                    Progress::for_plan(&plan)
                } else {
                    p
                }
            }
            Err(e) => {
                eprintln!("warning: no hay progreso recuperable ({e}); arrancando limpio");
                Progress::for_plan(&plan)
            }
        }
    } else {
        // Fresh: borra cualquier progreso anterior.
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
    eprintln!(
        "device: {device}\nplan: {} entries (preset {:?}), batch_size {}",
        plan.entries.len(),
        plan.preset,
        plan.batch_size
    );

    // ---------- 6. Bucle principal ----------
    let started = Instant::now();
    let total_configs = plan.entries.len();

    for cfg_idx in 0..total_configs {
        let cfg: ConfigEntry = plan.entries[cfg_idx];
        if progress.per_config[cfg_idx].next_step >= N {
            // Ya completada (o marcada por skip/only).
            continue;
        }
        progress.current_config = cfg_idx;

        let start_idx = progress.per_config[cfg_idx].next_step;
        eprintln!(
            "[cfg {}/{}] {} (klen {} B), arranca en idx {}",
            cfg_idx + 1,
            total_configs,
            cfg.display_id(),
            cfg.key_len_bytes(),
            start_idx
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

        loop {
            // Stop flag — se respeta entre batches, no a media GPU.
            if stop.load(Ordering::SeqCst) {
                progress.last_flush_utc = utc_now();
                save_progress_with_bak(&progress_path, &progress)?;
                let elapsed = started.elapsed().as_secs_f64();
                eprintln!(
                    "[pausa] elapsed={:.2}s; estado guardado en {}. \
                     Reanuda con `quattro-crack run --resume`.",
                    elapsed,
                    progress_path.display()
                );
                return Ok(RunOutcome::Paused {
                    elapsed_secs: elapsed,
                    last_config: cfg_idx,
                    last_step: progress.per_config[cfg_idx].next_step,
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

            // Avanza puntero ANTES de validar hits (next_step indica el
            // siguiente idx NO probado; el batch que acaba de terminar
            // ya cubre [next_step, next_step + idx_count)).
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
                        let hit = Hit {
                            idx: dh.idx,
                            config: cfg,
                            password: std::str::from_utf8(pw_utf8)
                                .unwrap_or("<no utf8>")
                                .to_string(),
                            plaintext_hex: hex::encode(&plaintext),
                            when_utc: utc_now(),
                        };
                        progress.hits.push(hit.clone());
                        progress.last_flush_utc = utc_now();
                        save_progress_with_bak(&progress_path, &progress)?;
                        let elapsed = started.elapsed().as_secs_f64();
                        eprintln!("================================================================");
                        eprintln!(
                            "  HIT CONFIRMADO  cfg={}  idx={}  pw='{}'",
                            cfg.display_id(),
                            hit.idx,
                            hit.password
                        );
                        eprintln!(
                            "  elapsed={:.2}s   plaintext[..32]={}",
                            elapsed,
                            &hit.plaintext_hex[..64.min(hit.plaintext_hex.len())]
                        );
                        eprintln!("================================================================");
                        return Ok(RunOutcome::Found {
                            hit,
                            elapsed_secs: elapsed,
                        });
                    }
                    HitVerdict::Pkcs7Mismatch { .. } => {
                        // CRITICAL — D-007: ~2^-130 bajo CBC+PKCS7 real.
                        eprintln!("================================================================");
                        eprintln!(
                            "CRITICAL: prefijo-32 OK pero PKCS7 INVÁLIDO en idx={} cfg={}",
                            dh.idx,
                            cfg.display_id()
                        );
                        eprintln!("Probabilidad bajo CBC+PKCS7 real: ~2^-130 → casi seguro un BUG.");
                        eprintln!("Posibles causas: KDF rota / kernel rota / ciphertext corrupto.");
                        eprintln!("ABORTANDO el barrido. Estado guardado para inspección.");
                        eprintln!("================================================================");
                        progress.last_flush_utc = utc_now();
                        save_progress_with_bak(&progress_path, &progress)?;
                        return Err(anyhow!(
                            "Pkcs7Mismatch evento crítico (idx={}, cfg={}) — ver D-007",
                            dh.idx,
                            cfg.display_id()
                        ));
                    }
                    HitVerdict::PrefixMismatch32 => {
                        // Falso positivo del kernel (~2^-128 por candidata). Continuar.
                    }
                }
            }

            // Persistencia atómica al final de cada batch (§7.2).
            progress.last_flush_utc = utc_now();
            save_progress_with_bak(&progress_path, &progress)?;

            // Log periódico (cada 10 batches).
            if batches_run % 10 == 0 {
                let cfg_pct = 100.0 * (next_step + idx_count) as f64 / N as f64;
                let ghs = idx_count as f64 / batch_elapsed.as_secs_f64() / 1.0e9;
                eprintln!(
                    "  cfg {}/{}: batch #{:>5} idx={:>15} ({:.4}% del cfg) {:.2} GH/s",
                    cfg_idx + 1,
                    total_configs,
                    batches_run,
                    next_step,
                    cfg_pct,
                    ghs
                );
            }
        }

        eprintln!(
            "[cfg {}/{}] {} completada",
            cfg_idx + 1,
            total_configs,
            cfg.display_id()
        );
    }

    // Plan completado sin hit.
    progress.last_flush_utc = utc_now();
    save_progress_with_bak(&progress_path, &progress)?;
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!("plan completado SIN hit confirmado ({:.2}s)", elapsed);
    Ok(RunOutcome::Completed {
        elapsed_secs: elapsed,
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

fn progress_bak_path(path: &std::path::Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}
