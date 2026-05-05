//! build.rs — compila los kernels CUDA a PTX para `sm_120` (Blackwell)
//! con fallback documentado a `sm_89` (Ada) si nvcc < 12.8.
//!
//! Estrategia (D-011):
//!   - **Un único** `kernels/brute.cu` se compila **9 veces** con
//!     `-DKDF_ID=<0..8> -DKEY_LEN=<16|32>`, una por KDF.
//!   - El kernel auxiliar `kernels/dump_passwords.cu` se compila una vez.
//!   - Todos los PTX van a `OUT_DIR/<name>.ptx` y se embeben con
//!     `include_bytes!` en `src/cuda.rs`.
//!
//! Errores duros si nvcc falta. Cero "fallback silencioso a CPU" —
//! cualquier fallo aquí rompe el build con mensaje accionable.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Tabla de KDFs paralela al `Kdf::all()` de Rust:
/// (kdf_id, key_len, nombre). Los IDs 0..8 son contrato — no renumerar.
const KDFS: &[(u32, u32, &str)] = &[
    // 0..8 originales (Fase 3)
    (0, 16, "md5_utf8"),
    (1, 16, "md5_utf16le"),
    (2, 16, "md5_utf16be"),
    (3, 16, "md5x2_utf8"),
    (4, 32, "md5_dup"),
    (5, 32, "md5_md5rev"),
    (6, 32, "md5hex_full"),
    (7, 16, "md5hex_lo16"),
    (8, 16, "pw_padded"),
    // 9..13 ampliación Fase 3.5
    (9,  32, "evp_md5_aes256_nosalt"),
    (10, 24, "evp_md5_aes192_nosalt"),
    (11, 24, "md5_trunc24"),
    (12, 24, "md5_md5x2_24"),
    (13, 24, "md5hex_lo24"),
];

/// Cabeceras compartidas — si cambia cualquiera, recompilar todo.
const SHARED_HEADERS: &[&str] = &[
    "kernels/gen.cuh",
    "kernels/md5.cuh",
    "kernels/aes.cuh",
];

/// Sources que producen PTX.
const KERNEL_SOURCES: &[&str] = &[
    "kernels/dump_passwords.cu",
    "kernels/md5_test.cu",
    "kernels/aes_test.cu",
    "kernels/brute.cu",
];

fn main() -> Result<()> {
    // Re-run triggers
    for f in SHARED_HEADERS.iter().chain(KERNEL_SOURCES.iter()) {
        println!("cargo:rerun-if-changed={f}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CUDA_HOME");
    println!("cargo:rerun-if-env-changed=NVCC");

    let nvcc = find_nvcc().context(
        "no se encontró `nvcc`. instala CUDA Toolkit ≥ 12.8 con sm_120 (Blackwell) y \
         exporta PATH=/usr/local/cuda-X.Y/bin:$PATH antes de compilar",
    )?;

    let arch = pick_arch(&nvcc).context("no se pudo elegir GPU arch para nvcc")?;
    println!("cargo:rustc-env=QC_CUDA_ARCH={arch}");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());

    // Smoke test: dump_passwords (paridad CPU↔GPU del generador).
    compile_ptx(
        &nvcc,
        &arch,
        Path::new("kernels/dump_passwords.cu"),
        &[],
        &out_dir.join("dump_passwords.ptx"),
        &profile,
    )?;

    // Tests de las primitivas: MD5 y AES contra vectores estándar.
    let md5_test_src = Path::new("kernels/md5_test.cu");
    if md5_test_src.exists() {
        compile_ptx(
            &nvcc,
            &arch,
            md5_test_src,
            &[],
            &out_dir.join("md5_test.ptx"),
            &profile,
        )?;
    }
    let aes_test_src = Path::new("kernels/aes_test.cu");
    if aes_test_src.exists() {
        compile_ptx(
            &nvcc,
            &arch,
            aes_test_src,
            &[],
            &out_dir.join("aes_test.ptx"),
            &profile,
        )?;
    }

    let force_emit_src = Path::new("kernels/force_emit_hits.cu");
    if force_emit_src.exists() {
        compile_ptx(
            &nvcc,
            &arch,
            force_emit_src,
            &[],
            &out_dir.join("force_emit_hits.ptx"),
            &profile,
        )?;
    }

    // 9 variantes del kernel principal — cuando exista brute.cu.
    let brute_src = Path::new("kernels/brute.cu");
    if brute_src.exists() {
        for (kdf_id, key_len, name) in KDFS {
            let defines = [
                format!("-DKDF_ID={kdf_id}"),
                format!("-DKEY_LEN={key_len}"),
            ];
            let out = out_dir.join(format!("brute_{kdf_id}.ptx"));
            compile_ptx(&nvcc, &arch, brute_src, &defines, &out, &profile)
                .with_context(|| format!("compilando brute.cu para {name} (id={kdf_id})"))?;
        }
    } else {
        println!("cargo:warning=kernels/brute.cu no existe todavía; salto compilación de variantes");
    }

    Ok(())
}

fn find_nvcc() -> Result<PathBuf> {
    // 1. Variable de entorno explícita.
    if let Some(p) = env::var_os("NVCC") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
    }
    // 2. CUDA_HOME / CUDA_PATH.
    for k in ["CUDA_HOME", "CUDA_PATH"] {
        if let Some(home) = env::var_os(k) {
            let cand = PathBuf::from(home).join("bin").join("nvcc");
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    // 3. PATH.
    if let Ok(out) = Command::new("which").arg("nvcc").output() {
        if out.status.success() {
            let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !path.is_empty() {
                let p = PathBuf::from(path);
                if p.is_file() {
                    return Ok(p);
                }
            }
        }
    }
    // 4. Rutas habituales en Linux/WSL.
    for cand in [
        "/usr/local/cuda/bin/nvcc",
        "/usr/local/cuda-13.0/bin/nvcc",
        "/usr/local/cuda-12.9/bin/nvcc",
        "/usr/local/cuda-12.8/bin/nvcc",
    ] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return Ok(p);
        }
    }
    Err(anyhow!("nvcc no encontrado en NVCC, CUDA_HOME, PATH, ni rutas conocidas"))
}

/// Elige `sm_120` si nvcc lo soporta; si no, cae a `sm_89` con warning visible.
fn pick_arch(nvcc: &Path) -> Result<String> {
    let preferred = "sm_120";
    let fallback = "sm_89";

    // Smoke test: intenta compilar un .cu vacío con -arch=sm_120.
    let tmp = env::temp_dir().join("qc_arch_probe.cu");
    std::fs::write(&tmp, "__global__ void k(){}\n")?;

    let probe = Command::new(nvcc)
        .args(["-arch", preferred, "-ptx", "-o", "-"])
        .arg(&tmp)
        .output();

    let _ = std::fs::remove_file(&tmp);

    if let Ok(out) = probe {
        if out.status.success() {
            return Ok(preferred.into());
        }
    }

    println!(
        "cargo:warning=Compilando para {fallback} (Ada). Para {preferred} nativo \
         (Blackwell, RTX 50xx) actualiza CUDA Toolkit a ≥ 12.8."
    );
    Ok(fallback.into())
}

fn compile_ptx(
    nvcc: &Path,
    arch: &str,
    src: &Path,
    extra_defines: &[String],
    out_ptx: &Path,
    profile: &str,
) -> Result<()> {
    let mut cmd = Command::new(nvcc);
    cmd.arg("-arch").arg(arch);
    cmd.arg("-std=c++17");
    cmd.arg("--use_fast_math");
    cmd.arg("-Xcompiler").arg("-fPIC");

    if profile == "release" {
        cmd.arg("-O3").arg("-lineinfo");
    } else {
        // -G es lento y rompe coverage de paridad CPU↔GPU; en debug nos
        // basta con -O0 y `-lineinfo`. Si haces falta debugging device
        // serio, recompila a mano con `-G`.
        cmd.arg("-O0").arg("-lineinfo");
    }

    for d in extra_defines {
        cmd.arg(d);
    }

    cmd.arg("-ptx")
        .arg(src)
        .arg("-o")
        .arg(out_ptx);

    let out = cmd
        .output()
        .with_context(|| format!("ejecutando nvcc en {}", src.display()))?;
    if !out.status.success() {
        bail!(
            "nvcc falló compilando {} → {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            src.display(),
            out_ptx.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    Ok(())
}
