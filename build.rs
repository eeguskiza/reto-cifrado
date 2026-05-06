//! build.rs — compila los kernels CUDA a PTX para `sm_120` (Blackwell)
//! con fallback documentado a `sm_89` (Ada) si nvcc < 12.8.
//!
//! Tras D-029, **un único** PTX activo: `brute_md5hex_aes256_ecb.ptx`,
//! sin parametrizar por KDF/KEY_LEN/MODE. El kernel parametrizado de
//! Fase 3.5 (`brute.cu`, 14 PTX por KDF) se archiva como
//! `brute_legacy_phase6.cu` y NO se compila.
//!
//! Errores duros si nvcc falta. Cero "fallback silencioso a CPU" —
//! cualquier fallo aquí rompe el build con mensaje accionable.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};

/// Cabeceras compartidas — si cambia cualquiera, recompilar todo.
const SHARED_HEADERS: &[&str] = &[
    "kernels/gen.cuh",
    "kernels/md5.cuh",
    "kernels/aes.cuh",
    "kernels/aes_tables.cuh",
];

/// Sources que producen PTX activos (D-029).
const KERNEL_SOURCES: &[&str] = &[
    "kernels/dump_passwords.cu",
    "kernels/md5_test.cu",
    "kernels/aes_test.cu",
    "kernels/force_emit_hits.cu",
    "kernels/dump_pt_block0.cu",
    "kernels/brute_md5hex_aes256_ecb.cu",
];

fn main() -> Result<()> {
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

    // Helpers de paridad CPU↔GPU del generador.
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
    let dump_pt_src = Path::new("kernels/dump_pt_block0.cu");
    if dump_pt_src.exists() {
        compile_ptx(
            &nvcc,
            &arch,
            dump_pt_src,
            &[],
            &out_dir.join("dump_pt_block0.ptx"),
            &profile,
        )?;
    }

    // ÚNICO PTX activo del barrido (D-029).
    let brute_src = Path::new("kernels/brute_md5hex_aes256_ecb.cu");
    if !brute_src.exists() {
        bail!(
            "kernels/brute_md5hex_aes256_ecb.cu no existe — refactor D-029 incompleto"
        );
    }
    compile_ptx(
        &nvcc,
        &arch,
        brute_src,
        &[],
        &out_dir.join("brute_md5hex_aes256_ecb.ptx"),
        &profile,
    )
    .context("compilando brute_md5hex_aes256_ecb.cu")?;

    Ok(())
}

fn find_nvcc() -> Result<PathBuf> {
    if let Some(p) = env::var_os("NVCC") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Ok(p);
        }
    }
    for k in ["CUDA_HOME", "CUDA_PATH"] {
        if let Some(home) = env::var_os(k) {
            let cand = PathBuf::from(home).join("bin").join("nvcc");
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
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

fn pick_arch(nvcc: &Path) -> Result<String> {
    let preferred = "sm_120";
    let fallback = "sm_89";

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
        cmd.arg("-O0").arg("-lineinfo");
    }

    for d in extra_defines {
        cmd.arg(d);
    }

    cmd.arg("-ptx").arg(src).arg("-o").arg(out_ptx);

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
