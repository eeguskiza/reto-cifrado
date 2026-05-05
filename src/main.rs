use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use quattro_crack::ciphertext::{Ciphertext, CT_BLOCKS, CT_LEN, IV_LEN, TOTAL_BIN_LEN};
use quattro_crack::plan::{default_plan_order, Plan, Preset};
use quattro_crack::state::{load_plan, load_progress};

#[derive(Parser, Debug)]
#[command(
    name = "quattro-crack",
    version,
    about = "Brute-force CUDA contra AES-CBC + MD5 con estructura de password conocida"
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

    /// Imprime el plan de barrido resuelto para el preset elegido.
    Plan {
        #[arg(long, value_enum, default_value_t = PresetCli::Exhaustive)]
        preset: PresetCli,

        /// Ruta al fichero objetivo (para incluir su SHA-256 en el plan).
        #[arg(long, default_value = "./data/cifrado.txt")]
        input: PathBuf,

        /// Tamaño de batch del kernel (Fase 3). Default = 16 Mi.
        #[arg(long, default_value_t = 16_777_216)]
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
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum PresetCli {
    Canonical,
    Likely,
    Exhaustive,
}

impl From<PresetCli> for Preset {
    fn from(p: PresetCli) -> Self {
        match p {
            PresetCli::Canonical => Preset::Canonical,
            PresetCli::Likely => Preset::Likely,
            PresetCli::Exhaustive => Preset::Exhaustive,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Inspect { path } => inspect(&path),
        Cmd::Plan {
            preset,
            input,
            batch_size,
            save,
        } => plan_cmd(preset.into(), &input, batch_size, save),
        Cmd::Status { state_dir } => status_cmd(&state_dir),
    }
}

fn inspect(path: &Path) -> Result<()> {
    let ct = Ciphertext::load(path).with_context(|| format!("cargando {}", path.display()))?;

    println!("file:         {}", ct.source_path.display());
    println!(
        "size:         {} B  ({} IV + {} CT = {} bloques AES de 16 B)",
        TOTAL_BIN_LEN, IV_LEN, CT_LEN, CT_BLOCKS
    );
    println!("iv:           {}", hex::encode(ct.iv()));
    println!("ct[0..32]:    {}", hex::encode(&ct.ct()[..32]));
    println!("sha256(file): {}", hex::encode(ct.source_sha256));
    Ok(())
}

fn plan_cmd(preset: Preset, input: &Path, batch_size: u32, save: bool) -> Result<()> {
    let ct = Ciphertext::load(input).with_context(|| format!("cargando {}", input.display()))?;
    let sha_hex = hex::encode(ct.source_sha256);

    let plan = Plan::from_preset(
        env!("CARGO_PKG_VERSION"),
        ct.source_path.display().to_string(),
        sha_hex.clone(),
        preset,
        batch_size,
    )
    .context("construyendo plan")?;

    println!("plan         preset: {}", preset.as_str());
    println!("source       {}", plan.source_path);
    println!("sha256       {}", plan.source_sha256);
    println!("batch_size   {}", plan.batch_size);
    println!("entries      {}", plan.entries.len());
    println!();
    println!("{:>3}  kdf            mode  iv         klen", "#");
    for (i, c) in plan.entries.iter().enumerate() {
        println!(
            "{:>3}. {:<14} {:<5} {:<10} {} B",
            i + 1,
            c.kdf.as_str(),
            c.mode.as_str(),
            c.iv.as_str(),
            c.key_len_bytes(),
        );
    }

    if save {
        let path = PathBuf::from("./state/plan.toml");
        quattro_crack::state::save_plan(&path, &plan)
            .with_context(|| format!("guardando {}", path.display()))?;
        println!();
        println!("plan guardado en {}", path.display());
    } else {
        // Default order completo en background (incluyendo entries fuera del preset)
        // para que el usuario pueda comprobar que el orden es el documentado.
        let full = default_plan_order();
        if plan.entries.len() < full.len() {
            println!();
            println!(
                "(preset reduce a {} de {} configuraciones; pasa --preset exhaustive \
                 para ver el plan completo, o --save para escribir state/plan.toml)",
                plan.entries.len(),
                full.len()
            );
        }
    }
    Ok(())
}

fn status_cmd(state_dir: &Path) -> Result<()> {
    let plan_path = state_dir.join("plan.toml");
    let prog_path = state_dir.join("progress.toml");

    if !plan_path.exists() {
        println!("no hay plan guardado en {}.", plan_path.display());
        println!("lanza `quattro-crack plan --preset <…> --save` para crearlo,");
        println!("o `quattro-crack run --resume` cuando exista runner (Fase 4).");
        return Ok(());
    }

    let plan = load_plan(&plan_path)
        .with_context(|| format!("leyendo {}", plan_path.display()))?;
    println!("plan         {} (v{})", plan_path.display(), plan.program_version);
    println!("source       {}", plan.source_path);
    println!("sha256       {}", plan.source_sha256);
    println!("preset       {:?}", plan.preset);
    println!("entries      {}", plan.entries.len());
    println!();

    if let Ok(progress) = load_progress(&prog_path) {
        println!("progress     {}", prog_path.display());
        println!(
            "current      cfg #{} of {}",
            progress.current_config + 1,
            plan.entries.len()
        );
        println!("hits         {}", progress.hits.len());
        println!("last_flush   {}", progress.last_flush_utc);
        for (i, p) in progress.per_config.iter().enumerate() {
            if i >= plan.entries.len() {
                break;
            }
            let e = &plan.entries[i];
            println!(
                "  cfg {:>2} {:<28} next_step={:>15}  tried={}",
                i + 1,
                e.display_id(),
                p.next_step,
                p.tried
            );
        }
    } else {
        println!("(sin progreso persistido todavía — ejecuta el runner para iniciar)");
    }
    Ok(())
}
