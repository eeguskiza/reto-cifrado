//! `test_resume_finds_key_after_pause` y `test_resume_rejects_modified_input`
//! — tests bloqueantes de Fase 4 (spec §10).

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
use quattro_crack::config::Kdf;
use quattro_crack::kdf::derive;
use quattro_crack::plan::{Plan, Preset};
use quattro_crack::reference::{encrypt_cbc_pkcs7, KNOWN_PREFIX_32};
use quattro_crack::runner::{self, RunOptions};
use quattro_crack::state::{load_progress, save_plan};

const QC_BIN: &str = env!("CARGO_BIN_EXE_quattro-crack");

fn build_plaintext_1584() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1584);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1584 {
        pt.push(b'X');
    }
    pt
}

fn write_cifrado(path: &Path, iv: &[u8; 16], ct: &[u8]) {
    let mut bin = Vec::with_capacity(16 + ct.len());
    bin.extend_from_slice(iv);
    bin.extend_from_slice(ct);
    let b64 = STANDARD.encode(&bin);
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
    let st = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()?;
    if !st.success() {
        return Err(anyhow!("kill -INT {pid} falló: {st:?}"));
    }
    Ok(())
}

#[test]
fn test_resume_finds_key_after_pause() {
    // Password con idx ≈ 1.7e9 (year=0, disp=2 → vowel positions [0,1,2,5]).
    // Lo bastante lejos del origen para que SIGINT a 1s caiga durante el barrido,
    // lo bastante cerca para que el run de resume termine en pocos segundos.
    let pw = b".aAabbabb1000.";
    let target_idx = password_to_index(pw).unwrap();
    eprintln!("target_idx = {target_idx}");

    // Setup criptográfico: AES-128 CBC + PKCS7 con iv=zeros y kdf=md5_utf8
    // (= primera config del preset canonical).
    let kdf = Kdf::Md5Utf8;
    let key = derive(kdf, pw);
    let iv = [0u8; 16];
    let pt = build_plaintext_1584();
    let ct = encrypt_cbc_pkcs7(key.as_slice(), &iv, &pt).unwrap();
    assert_eq!(ct.len(), 1600);

    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    write_cifrado(&input_path, &iv, &ct);

    // ---------- Run 1: lanzar, esperar 1 s, SIGINT ----------
    let started = Instant::now();
    let mut child = Command::new(QC_BIN)
        .args([
            "run",
            "--input",
            input_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--preset",
            "canonical",
            "--batch-size",
            "10000000",
        ])
        .spawn()
        .expect("spawn run 1");

    std::thread::sleep(Duration::from_millis(1500));
    send_sigint(child.id()).expect("SIGINT al subproceso");
    let exit1 = wait_timeout(&mut child, Duration::from_secs(30)).expect("run 1 exit");
    assert!(
        exit1.success(),
        "run 1 debería salir limpio tras SIGINT, exit={exit1:?}"
    );
    let elapsed1 = started.elapsed();
    eprintln!("run 1 elapsed: {:?}", elapsed1);

    // Verifica progress.toml
    let progress_path = state_dir.join("progress.toml");
    assert!(progress_path.exists(), "progress.toml debe existir tras pausa");
    let progress1 = load_progress(&progress_path).expect("progress.toml válido");
    assert_eq!(
        progress1.per_config.len(),
        4,
        "preset canonical = 4 configs"
    );
    let any_progress = progress1.per_config.iter().any(|p| p.next_step > 0);
    assert!(
        any_progress,
        "tras pausa, algún next_step debe ser > 0: {:?}",
        progress1.per_config
    );
    let next_step_after_run1 = progress1.per_config[0].next_step;
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
    let resume_elapsed = resume_started.elapsed();
    assert!(
        exit2.success(),
        "resume debería salir limpio, exit={exit2:?}"
    );
    eprintln!("resume elapsed: {:?}", resume_elapsed);

    // Verifica que el hit aparece en progress.hits
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
                progress2
                    .hits
                    .iter()
                    .map(|h| (h.idx, h.password.clone()))
                    .collect::<Vec<_>>()
            );
        });
    assert_eq!(hit.password, ".aAabbabb1000.");
    assert_eq!(hit.config.kdf, Kdf::Md5Utf8);

    // Monotonía de next_step (no regresión tras resume).
    assert!(
        progress2.per_config[0].next_step >= next_step_after_run1,
        "next_step debe ser monótono creciente; run1={} run2={}",
        next_step_after_run1,
        progress2.per_config[0].next_step
    );
}

#[test]
fn test_resume_rejects_modified_input() {
    // 1) Escribe cifrado.txt v1 y un plan.toml con su SHA-256.
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let pw = b".aAabbabb1000.";
    let key = derive(Kdf::Md5Utf8, pw);
    let iv1 = [1u8; 16];
    let pt = build_plaintext_1584();
    let ct1 = encrypt_cbc_pkcs7(key.as_slice(), &iv1, &pt).unwrap();
    write_cifrado(&input_path, &iv1, &ct1);

    // Plan persistido con el SHA-256 de v1.
    let ct_loaded = Ciphertext::load(&input_path).unwrap();
    let plan = Plan::from_preset(
        env!("CARGO_PKG_VERSION"),
        input_path.display().to_string(),
        hex::encode(ct_loaded.source_sha256),
        Preset::Canonical,
        16_777_216,
    )
    .unwrap();
    save_plan(&state_dir.join("plan.toml"), &plan).unwrap();

    // 2) Modifica cifrado.txt: nuevo IV (= cambia los bytes del fichero
    //    decodificado, por tanto el SHA-256 del fichero entero también).
    let iv2 = [2u8; 16];
    let ct2 = encrypt_cbc_pkcs7(key.as_slice(), &iv2, &pt).unwrap();
    write_cifrado(&input_path, &iv2, &ct2);

    let ct_loaded2 = Ciphertext::load(&input_path).unwrap();
    assert_ne!(
        hex::encode(ct_loaded.source_sha256),
        hex::encode(ct_loaded2.source_sha256),
        "el sha256 debe haber cambiado tras la modificación"
    );

    // 3) --resume contra el plan v1 + cifrado v2 → debe fallar con error.
    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size: 16_777_216,
        preset: Preset::Canonical,
        resume: true,
        force_resume: false,
        skip_configs: vec![],
        only_configs: vec![],
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
    // --resume sin plan.toml previo → error explícito.
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    let key = derive(Kdf::Md5Utf8, b".aAabbabb1000.");
    let iv = [3u8; 16];
    let pt = build_plaintext_1584();
    let ct = encrypt_cbc_pkcs7(key.as_slice(), &iv, &pt).unwrap();
    write_cifrado(&input_path, &iv, &ct);

    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size: 16_777_216,
        preset: Preset::Canonical,
        resume: true,
        force_resume: false,
        skip_configs: vec![],
        only_configs: vec![],
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
