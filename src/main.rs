//! `quattro-crack` — CLI tras D-029.
//!
//! El barrido tiene una **única configuración** (`md5hex_full /
//! aes-256-ecb / pkcs7`), así que los flags `--preset`, `--kdf`, `--iv`,
//! `--skip-config` y `--only-config` se eliminan.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_appender::non_blocking::WorkerGuard;

use quattro_crack::ciphertext::{Ciphertext, CT_BLOCKS, TOTAL_BIN_LEN};
use quattro_crack::combinatorics::N as N_TOTAL;
use quattro_crack::cuda::{CudaCtx, KernelBundle, KernelBundleCoop};
use quattro_crack::gpu_metrics::GpuMonitor;
use quattro_crack::plan::{Plan, PLAN_FORMAT_VERSION, SINGLE_PLAN_DESCRIPTION};
use quattro_crack::runner::{self, ProgressSink, RunOptions, RunOutcome, StderrSink};
use quattro_crack::state::{load_plan, load_progress};
use quattro_crack::tui::{TuiSink, TuiSinkConfig};

#[derive(Parser, Debug)]
#[command(
    name = "quattro-crack",
    version,
    about = "Brute-force CUDA contra AES-256-ECB + md5hex_full (D-029)"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Inspecciona el fichero objetivo y muestra metadatos.
    Inspect {
        /// Ruta al fichero base64 con el ciphertext.
        #[arg(value_name = "PATH", default_value = "./data/cifrado.txt")]
        path: PathBuf,
    },

    /// Imprime el plan único de barrido (D-029).
    Plan {
        /// Ruta al fichero objetivo (para incluir su SHA-256 en el plan).
        #[arg(long, default_value = "./data/cifrado.txt")]
        input: PathBuf,

        /// Tamaño de batch del kernel.
        #[arg(long, default_value_t = 67_108_864)]
        batch_size: u32,

        /// Si se pasa, escribe `plan.toml` en `state/`.
        #[arg(long)]
        save: bool,
    },

    /// Resumen del estado actual (plan + progreso) sin lanzar barrido.
    Status {
        #[arg(long, default_value = "./state")]
        state_dir: PathBuf,
    },

    /// Ejecuta el barrido único. SIGINT/SIGTERM termina el batch en
    /// curso, guarda el estado y sale. Ver D-025/D-026/D-029.
    Run {
        /// Ruta al fichero base64 con el ciphertext.
        #[arg(long, default_value = "./data/cifrado.txt")]
        input: PathBuf,

        /// Directorio donde viven `plan.toml` y `progress.toml`.
        #[arg(long, default_value = "./state")]
        state_dir: PathBuf,

        /// Tamaño de batch del kernel. Default 64 Mi (D-025).
        #[arg(long, default_value_t = 67_108_864)]
        batch_size: u32,

        /// Cada cuántos batches se persiste `progress.toml` con `fsync`
        /// (D-026). Default 8.
        #[arg(long, default_value_t = 8)]
        flush_every: u32,

        /// Reanuda una sesión previa. Verifica SHA-256 del input.
        #[arg(long)]
        resume: bool,

        /// Ignora el chequeo de major version al reanudar.
        #[arg(long)]
        force_resume: bool,

        /// Fuerza salida tipo Fase 4 a stderr aunque haya TTY.
        #[arg(long)]
        no_tui: bool,

        /// Directorio donde se escriben los logs.
        #[arg(long, default_value = "./logs")]
        log_dir: PathBuf,
    },

    /// Borra `state/plan.toml`, `state/progress.toml` y sus `.bak`.
    Reset {
        #[arg(long, default_value = "./state")]
        state_dir: PathBuf,
        #[arg(long)]
        yes: bool,
    },

    /// Mide throughput sostenido del kernel único (D-029) sobre un
    /// ct_block_0 que no genera hits.
    ///
    /// Códigos de salida: 0 si ≥ 3 GH/s, 1 si 2 ≤ x < 3, 2 si < 2.
    Benchmark {
        /// Duración total objetivo de la medición (segundos).
        #[arg(long, default_value_t = 30)]
        duration: u64,

        /// Tamaño de cada batch lanzado al kernel.
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        batch_size: u64,

        /// Usar el kernel COOPERATIVO intra-warp (D-030) en vez del legacy.
        #[arg(long, default_value_t = false)]
        coop: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Inspect { path } => inspect(&path),
        Cmd::Plan {
            input,
            batch_size,
            save,
        } => plan_cmd(&input, batch_size, save),
        Cmd::Status { state_dir } => status_cmd(&state_dir),
        Cmd::Run {
            input,
            state_dir,
            batch_size,
            flush_every,
            resume,
            force_resume,
            no_tui,
            log_dir,
        } => run_cmd(
            RunOptions {
                input_path: input,
                state_dir,
                batch_size,
                resume,
                force_resume,
                flush_every_n_batches: flush_every,
            },
            no_tui,
            &log_dir,
        ),
        Cmd::Reset { state_dir, yes } => reset_cmd(&state_dir, yes),
        Cmd::Benchmark {
            duration,
            batch_size,
            coop,
        } => benchmark_cmd(duration, batch_size, coop),
    }
}

fn inspect(path: &Path) -> Result<()> {
    let ct = Ciphertext::load(path).with_context(|| format!("cargando {}", path.display()))?;

    println!("file:         {}", ct.source_path.display());
    println!(
        "size:         {} B  ({} bloques AES-256-ECB de 16 B, sin IV)",
        TOTAL_BIN_LEN, CT_BLOCKS
    );
    println!("ct[0..32]:    {}", hex::encode(&ct.ct()[..32]));
    println!("sha256(file): {}", hex::encode(ct.source_sha256));
    Ok(())
}

fn plan_cmd(input: &Path, batch_size: u32, save: bool) -> Result<()> {
    let ct = Ciphertext::load(input).with_context(|| format!("cargando {}", input.display()))?;
    let sha_hex = hex::encode(ct.source_sha256);

    let plan = Plan::new_single(
        PLAN_FORMAT_VERSION,
        ct.source_path.display().to_string(),
        sha_hex.clone(),
        batch_size,
    );

    println!("plan         única configuración (D-029)");
    println!("config       {SINGLE_PLAN_DESCRIPTION}");
    println!("source       {}", plan.source_path);
    println!("sha256       {}", plan.source_sha256);
    println!("batch_size   {}", plan.batch_size);
    println!("N            {} candidatas", N_TOTAL);

    if save {
        let path = PathBuf::from("./state/plan.toml");
        quattro_crack::state::save_plan(&path, &plan)
            .with_context(|| format!("guardando {}", path.display()))?;
        println!();
        println!("plan guardado en {}", path.display());
    }
    Ok(())
}

fn status_cmd(state_dir: &Path) -> Result<()> {
    let plan_path = state_dir.join("plan.toml");
    let prog_path = state_dir.join("progress.toml");

    if !plan_path.exists() {
        println!("no hay plan guardado en {}.", plan_path.display());
        println!("lanza `quattro-crack plan --save` para crearlo,");
        println!("o `quattro-crack run` para arrancar el barrido.");
        return Ok(());
    }

    let plan = load_plan(&plan_path)
        .with_context(|| format!("leyendo {}", plan_path.display()))?;
    println!("plan         {} (v{})", plan_path.display(), plan.program_version);
    println!("config       {SINGLE_PLAN_DESCRIPTION}");
    println!("source       {}", plan.source_path);
    println!("sha256       {}", plan.source_sha256);
    println!("batch_size   {}", plan.batch_size);
    println!();

    if let Ok(progress) = load_progress(&prog_path) {
        println!("progress     {}", prog_path.display());
        let pct = 100.0 * (progress.next_step as f64) / (N_TOTAL as f64);
        println!(
            "next_step    {} ({:.4}% del espacio)",
            progress.next_step, pct
        );
        println!("tried        {}", progress.tried);
        println!("hits         {}", progress.hits.len());
        println!("last_flush   {}", progress.last_flush_utc);
        if progress.prefix32_mismatch_count > 0 {
            println!(
                "prefix32 mismatch    {} descartes (samples: idx={:?})",
                progress.prefix32_mismatch_count,
                progress.prefix32_mismatch_idx_samples
            );
        }
    } else {
        println!("(sin progreso persistido todavía — ejecuta `run` para iniciar)");
    }
    Ok(())
}

fn run_cmd(opts: RunOptions, no_tui: bool, log_dir: &Path) -> Result<()> {
    let _tracing_guard = init_tracing(log_dir).context("inicializando tracing")?;

    let stop = Arc::new(AtomicBool::new(false));
    quattro_crack::signal::install(Arc::clone(&stop)).context("instalando signal handlers")?;

    let use_tui = !no_tui && io::stdout().is_terminal();

    let sink: Arc<dyn ProgressSink> = if use_tui {
        Arc::new(TuiSink::new(TuiSinkConfig {
            n_total_candidates: N_TOTAL,
            project_version: env!("CARGO_PKG_VERSION").into(),
        }))
    } else {
        Arc::new(StderrSink::new())
    };

    let _gpu_monitor = if use_tui {
        Some(GpuMonitor::start(Arc::clone(&sink)))
    } else {
        None
    };

    let outcome = runner::run(opts, sink.as_ref(), stop)?;
    drop(_gpu_monitor);
    drop(sink);

    match outcome {
        RunOutcome::Found { hit, elapsed_secs } => {
            println!(
                "HIT  pw='{}' idx={} elapsed={:.2}s",
                hit.password, hit.idx, elapsed_secs
            );
            Ok(())
        }
        RunOutcome::Completed { elapsed_secs } => {
            println!("DONE  plan completado SIN hit ({:.2}s)", elapsed_secs);
            Ok(())
        }
        RunOutcome::Paused {
            elapsed_secs,
            last_step,
        } => {
            println!(
                "PAUSED elapsed={:.2}s  last_step={}",
                elapsed_secs, last_step
            );
            Ok(())
        }
    }
}

fn init_tracing(log_dir: &Path) -> Result<WorkerGuard> {
    std::fs::create_dir_all(log_dir)?;
    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let path = log_dir.join(format!("run-{ts}.log"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("abriendo log {}", path.display()))?;
    let (writer, guard) = tracing_appender::non_blocking(file);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .compact()
        .init();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log = %path.display(),
        "tracing initialized"
    );
    Ok(guard)
}

fn reset_cmd(state_dir: &Path, yes: bool) -> Result<()> {
    let plan_path = state_dir.join("plan.toml");
    let progress_path = state_dir.join("progress.toml");
    let progress_bak = state_dir.join("progress.toml.bak");
    let plan_bak = state_dir.join("plan.toml.bak");

    let exists_any = plan_path.exists()
        || progress_path.exists()
        || progress_bak.exists()
        || plan_bak.exists();
    if !exists_any {
        println!("nada que borrar en {}.", state_dir.display());
        return Ok(());
    }

    if !yes {
        eprintln!("Esto borrará:");
        for p in [&plan_path, &progress_path, &progress_bak, &plan_bak] {
            if p.exists() {
                eprintln!("  {}", p.display());
            }
        }
        eprint!("Continuar? [y/N] ");
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        let answer = input.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" && answer != "s" && answer != "si" {
            println!("cancelado.");
            return Ok(());
        }
    }

    for p in [&plan_path, &progress_path, &progress_bak, &plan_bak] {
        if p.exists() {
            std::fs::remove_file(p).with_context(|| format!("borrando {}", p.display()))?;
        }
    }
    println!("estado borrado.");
    Ok(())
}

fn benchmark_cmd(duration_secs: u64, batch_size: u64, coop: bool) -> Result<()> {
    let ctx = CudaCtx::init().context("CUDA init")?;
    let device = ctx.device_name().unwrap_or_else(|_| "<unknown>".into());

    // Selección de kernel: D-030 cooperativo o legacy. La elección se
    // resuelve con un enum interno para que el resto del código quede
    // genérico sobre la API `launch(idx_base, idx_count, ct_block_0)`.
    enum Bundle {
        Legacy(KernelBundle),
        Coop(KernelBundleCoop),
    }
    impl Bundle {
        fn launch(&mut self, ib: u64, ic: u64, ct: &[u8; 16]) -> Result<()> {
            match self {
                Bundle::Legacy(b) => {
                    b.launch(ib, ic, ct)?;
                }
                Bundle::Coop(b) => {
                    b.launch(ib, ic, ct)?;
                }
            }
            Ok(())
        }
    }

    let mut bundle = if coop {
        Bundle::Coop(KernelBundleCoop::load(&ctx).context("cargando kernel coop D-030")?)
    } else {
        Bundle::Legacy(KernelBundle::load(&ctx).context("cargando kernel legacy")?)
    };

    // CT block aleatorio improbable de matchear "Leonardo da Vinc".
    let ct_block_0 = [0xffu8; 16];

    println!("device       : {device}");
    println!("kernel       : {}", if coop { "D-030 cooperative intra-warp" } else { "legacy single-thread" });
    println!("config       : {SINGLE_PLAN_DESCRIPTION}");
    println!("batch size   : {batch_size} ({:.2} Mi)", batch_size as f64 / (1u64 << 20) as f64);
    println!("duration tgt : {duration_secs}s");
    println!();

    bundle
        .launch(0, batch_size.min(16 * 1024 * 1024), &ct_block_0)
        .context("warmup launch")?;

    let total_target = std::time::Duration::from_secs(duration_secs);
    let mut total_candidates: u64 = 0;
    let mut total_elapsed = std::time::Duration::ZERO;
    let mut peak_ghs: f64 = 0.0;
    let mut runs: Vec<f64> = Vec::new();

    let started = std::time::Instant::now();
    let mut idx_base: u64 = 0;
    while started.elapsed() < total_target {
        let t0 = std::time::Instant::now();
        bundle
            .launch(idx_base, batch_size, &ct_block_0)
            .context("benchmark launch")?;
        let dt = t0.elapsed();
        let ghs = batch_size as f64 / dt.as_secs_f64() / 1.0e9;
        runs.push(ghs);
        if ghs > peak_ghs {
            peak_ghs = ghs;
        }
        total_candidates += batch_size;
        total_elapsed += dt;
        idx_base = idx_base.wrapping_add(batch_size);
        eprintln!(
            "  batch #{:>3}: {:>8.3} GH/s ({:>5} ms, idx_base={})",
            runs.len(),
            ghs,
            dt.as_millis(),
            idx_base.wrapping_sub(batch_size)
        );
    }

    let avg_ghs = total_candidates as f64 / total_elapsed.as_secs_f64() / 1.0e9;
    let mut sorted = runs.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if sorted.is_empty() {
        0.0
    } else {
        sorted[sorted.len() / 2]
    };

    println!();
    println!("--- result ---");
    println!("batches      : {}", runs.len());
    println!("total cand   : {total_candidates}");
    println!("total time   : {:.3}s", total_elapsed.as_secs_f64());
    println!("peak GH/s    : {peak_ghs:.3}");
    println!("avg  GH/s    : {avg_ghs:.3}");
    println!("median GH/s  : {median:.3}");

    let target = 3.0;
    let warn = 2.0;
    let exit_code: i32 = if avg_ghs >= target {
        println!("STATUS       : OK (≥ {target:.1} GH/s)");
        0
    } else if avg_ghs >= warn {
        println!("STATUS       : WARNING ({avg_ghs:.3} GH/s entre {warn:.1} y {target:.1})");
        1
    } else {
        println!("STATUS       : REGRESSION ({avg_ghs:.3} GH/s < {warn:.1} GH/s)");
        2
    };
    std::process::exit(exit_code);
}
