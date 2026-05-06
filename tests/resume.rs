//! Tests bloqueantes Fase 4 + adaptados a D-029.

use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::ciphertext::Ciphertext;
use quattro_crack::combinatorics::password_to_index;
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::plan::{Plan, PLAN_FORMAT_VERSION};
use quattro_crack::reference::{encrypt_ecb_pkcs7, KNOWN_PREFIX_32};
use quattro_crack::runner::{self, RunOptions};
use quattro_crack::state::{load_progress, save_plan};

const QC_BIN: &str = env!("CARGO_BIN_EXE_quattro-crack");

fn build_plaintext_1600() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }
    pt
}

/// Escribe `cifrado.txt` con base64 del CT ECB (sin IV, 1616 B = 101 bloques).
fn write_cifrado_ecb(path: &Path, ct_1616: &[u8]) {
    assert_eq!(ct_1616.len(), 1616);
    let b64 = STANDARD.encode(ct_1616);
    std::fs::write(path, b64).unwrap();
}

fn wait_timeout(child: &mut Child, timeout: Duration) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            return Err(anyhow!("timeout esperando al subproceso"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn send_sigint(pid: u32) -> Result<()> {
    let st = Command::new("kill").args(["-INT", &pid.to_string()]).status()?;
    if !st.success() {
        return Err(anyhow!("kill -INT {pid} falló: {st:?}"));
    }
    Ok(())
}

#[test]
fn test_resume_finds_key_after_pause() {
    // Password con idx ≈ 1.7e9 — al alcance del barrido en pocos segundos.
    let pw = b".aAabbabb1000.";
    let target_idx = password_to_index(pw).unwrap();
    eprintln!("target_idx = {target_idx}");

    let key = derive_md5hex(pw);
    let pt = build_plaintext_1600();
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    assert_eq!(ct.len(), 1616);

    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    write_cifrado_ecb(&input_path, &ct);

    // ---------- Run 1: lanzar, esperar 500 ms, SIGINT ----------
    // Tras D-029 el kernel es ECB md5hex AES-256 (más lento que md5_utf8
    // AES-128). 500 ms × ~1.6 GH/s ≈ 800 M candidatas, muy por debajo
    // de target_idx ≈ 1.7 G ⇒ SIGINT atrapa al barrido en plena marcha.
    let started = Instant::now();
    let mut child = Command::new(QC_BIN)
        .args([
            "run",
            "--input",
            input_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--batch-size",
            "10000000",
            "--flush-every",
            "1",
        ])
        .spawn()
        .expect("spawn run 1");
    std::thread::sleep(Duration::from_millis(500));
    send_sigint(child.id()).expect("SIGINT al subproceso");
    let exit1 = wait_timeout(&mut child, Duration::from_secs(30)).expect("run 1 exit");
    assert!(exit1.success(), "run 1 debería salir limpio, exit={exit1:?}");
    eprintln!("run 1 elapsed: {:?}", started.elapsed());

    let progress_path = state_dir.join("progress.toml");
    assert!(progress_path.exists(), "progress.toml debe existir tras pausa");
    let progress1 = load_progress(&progress_path).expect("progress.toml válido");
    assert!(
        progress1.next_step > 0,
        "tras pausa, next_step debe ser > 0: {:?}",
        progress1
    );
    let next_step_after_run1 = progress1.next_step;
    eprintln!("next_step tras run 1: {next_step_after_run1}");

    // ---------- Run 2: --resume ----------
    let resume_started = Instant::now();
    let exit2 = Command::new(QC_BIN)
        .args([
            "run",
            "--input",
            input_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--resume",
        ])
        .status()
        .expect("run 2 status");
    eprintln!("resume elapsed: {:?}", resume_started.elapsed());
    assert!(exit2.success(), "resume debería salir limpio, exit={exit2:?}");

    let progress2 = load_progress(&progress_path).unwrap();
    assert!(
        !progress2.hits.is_empty(),
        "debería haber al menos un hit confirmado"
    );
    let hit = progress2
        .hits
        .iter()
        .find(|h| h.idx == target_idx)
        .unwrap_or_else(|| {
            panic!(
                "target_idx={target_idx} no aparece. hits encontradas: {:?}",
                progress2.hits.iter().map(|h| (h.idx, h.password.clone())).collect::<Vec<_>>()
            );
        });
    assert_eq!(hit.password, ".aAabbabb1000.");
    assert!(
        progress2.next_step >= next_step_after_run1,
        "next_step debe ser monótono creciente; run1={} run2={}",
        next_step_after_run1,
        progress2.next_step
    );
}

#[test]
fn test_resume_rejects_modified_input() {
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let pw = b".aAabbabb1000.";
    let key = derive_md5hex(pw);
    let pt = build_plaintext_1600();
    let ct1 = encrypt_ecb_pkcs7(&key, &pt);
    write_cifrado_ecb(&input_path, &ct1);

    let ct_loaded = Ciphertext::load(&input_path).unwrap();
    let plan = Plan::new_single(
        PLAN_FORMAT_VERSION,
        input_path.display().to_string(),
        hex::encode(ct_loaded.source_sha256),
        16_777_216,
    );
    save_plan(&state_dir.join("plan.toml"), &plan).unwrap();

    // Modifica el fichero: cambia un byte del CT (cambia el sha256 sin
    // cambiar el tamaño).
    let mut ct2 = ct1.clone();
    ct2[0] ^= 0xff;
    write_cifrado_ecb(&input_path, &ct2);
    let ct_loaded2 = Ciphertext::load(&input_path).unwrap();
    assert_ne!(
        hex::encode(ct_loaded.source_sha256),
        hex::encode(ct_loaded2.source_sha256),
        "el sha256 debe haber cambiado tras la modificación"
    );

    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size: 16_777_216,
        resume: true,
        force_resume: false,
        flush_every_n_batches: 1,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let sink = quattro_crack::runner::StderrSink::new();
    let result = runner::run(opts, &sink, stop);
    let err = result.expect_err("resume con SHA distinto debe fallar");
    let msg = format!("{err:?}");
    let lower = msg.to_lowercase();
    assert!(
        lower.contains("ha cambiado") || lower.contains("sha256") || lower.contains("sha-256"),
        "el error debería mencionar el cambio de fichero/sha256: {msg}"
    );
}

#[test]
fn test_resume_without_plan_fails_with_clear_message() {
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let key = derive_md5hex(b".aAabbabb1000.");
    let pt = build_plaintext_1600();
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    write_cifrado_ecb(&input_path, &ct);

    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size: 16_777_216,
        resume: true,
        force_resume: false,
        flush_every_n_batches: 1,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let sink = quattro_crack::runner::StderrSink::new();
    let err = runner::run(opts, &sink, stop).expect_err("resume sin plan.toml debe fallar");
    let msg = format!("{err:?}");
    assert!(
        msg.to_lowercase().contains("plan.toml")
            || msg.to_lowercase().contains("sesión previa")
            || msg.contains("--resume"),
        "el error debería pedir lanzar sin --resume: {msg}"
    );
}
