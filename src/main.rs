use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use quattro_crack::ciphertext::{Ciphertext, CT_BLOCKS, CT_LEN, IV_LEN, TOTAL_BIN_LEN};

#[derive(Parser, Debug)]
#[command(
    name = "quattro-crack",
    version,
    about = "Brute-force CUDA contra AES + MD5 con estructura de password conocida"
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::Inspect { path } => inspect(&path),
    }
}

fn inspect(path: &Path) -> Result<()> {
    let ct = Ciphertext::load(path)
        .with_context(|| format!("cargando {}", path.display()))?;

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
