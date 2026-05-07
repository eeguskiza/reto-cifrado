//! Tests bloqueantes Fase 7 + adaptados a D-035.
//!
//! 1. Throughput end-to-end del runner con la única configuración
//!    real (passraw + AES-128).
//! 2. Compatibilidad de fixtures: el `progress.toml` legacy de la
//!    sesión pre-D-029 (CBC, multi-config) debe ser RECHAZADO con
//!    error claro.
//! 3. Reanudación correcta entre flushes agrupados.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::ciphertext::TOTAL_BIN_LEN;
use quattro_crack::reference::{build_key_passraw, encrypt_cifraronline, KNOWN_PREFIX_32_LF};
use quattro_crack::runner::{self, ProgressEvent, ProgressSink, RunOptions, RunOutcome};
use quattro_crack::state::{load_progress_with_bak, save_progress_with_bak, Progress, StateError};

struct CountingSink {
    batches: AtomicU64,
}

impl CountingSink {
    fn new() -> Self {
        Self {
            batches: AtomicU64::new(0),
        }
    }
    fn batches(&self) -> u64 {
        self.batches.load(Ordering::Relaxed)
    }
}

impl ProgressSink for CountingSink {
    fn on_event(&self, event: ProgressEvent) {
        if matches!(event, ProgressEvent::BatchCompleted { .. }) {
            self.batches.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Construye un plaintext sintético que arranca con KNOWN_PREFIX_32_LF
/// y se rellena hasta cubrir 1616 B de ciphertext final (formato real
/// del fichero objetivo).
fn build_plaintext_for_1616_ct() -> Vec<u8> {
    // Ciphertext de 1616 B = 101 bloques. message debe terminar con
    // null pad de longitud (16 - len(message) % 16) % 16, y len(ct) =
    // len(padded). Para que ct = 1616, padded = 1616, message ≤ 1616 con
    // longitud que tras padding == 1616. Si message es múltiplo de 16,
    // padded == message. Más simple: message = 1616 - 32 (md5_hex) = 1584
    // B de plaintext_clean. Luego padded = 1616 exact.
    let mut pt = Vec::with_capacity(1584);
    pt.extend_from_slice(KNOWN_PREFIX_32_LF);
    while pt.len() < 1584 {
        pt.push(b'X');
    }
    pt.truncate(1584);
    pt
}

/// Cifra un PT bajo passraw / AES-128-ECB con una clave que NO está
/// en el rango barrido — el runner barrerá sin encontrar nada.
fn write_synthetic_cifrado(path: &Path) {
    let pw = b".aAabbabb1999.";
    let key = build_key_passraw(pw);
    let pt = build_plaintext_for_1616_ct();
    let ct = encrypt_cifraronline(&key, &pt);
    assert_eq!(ct.len(), TOTAL_BIN_LEN);
    let b64 = STANDARD.encode(&ct);
    std::fs::write(path, b64).unwrap();
}

#[test]
fn test_real_run_throughput_meets_target() {
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    write_synthetic_cifrado(&input_path);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(5));
        stop_clone.store(true, Ordering::SeqCst);
    });

    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size: 64 * 1024 * 1024,
        resume: false,
        force_resume: false,
        flush_every_n_batches: 8,
    };

    let sink = CountingSink::new();
    let started = Instant::now();
    let outcome = runner::run(opts, &sink, stop).expect("runner debe terminar limpio");
    let elapsed = started.elapsed();

    let batches = sink.batches();
    let total = batches * (64u64 * 1024 * 1024);
    let ghs = total as f64 / elapsed.as_secs_f64() / 1.0e9;
    eprintln!(
        "real run D-035: batches={} total={} elapsed={:?} GH/s={:.3}",
        batches, total, elapsed, ghs
    );
    assert!(
        matches!(outcome, RunOutcome::Paused { .. }),
        "esperaba Paused, obtuve {outcome:?}"
    );
    // Tras D-035 (passraw + AES-128) el techo sube respecto a D-029.
    // Esperamos 4-7 GH/s sostenidos. Piso conservador 2.0 GH/s.
    assert!(
        ghs >= 2.0,
        "throughput end-to-end {ghs:.3} GH/s < 2.0 GH/s — regresión seria del runner D-035"
    );
}

#[test]
fn test_state_compat_with_pre_optimization_progress() {
    // El fixture legacy (con `[[per_config]]`) sigue siendo rechazado
    // post-D-035 igual que post-D-029.
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("legacy_progress.toml");
    assert!(
        fixture.exists(),
        "fixture {} no existe — debe estar comiteada al repo",
        fixture.display()
    );

    let err = load_progress_with_bak(&fixture)
        .expect_err("legacy progress.toml debe ser rechazado tras D-029/D-035");
    assert!(
        matches!(err, StateError::LegacyFormat { .. }),
        "esperaba LegacyFormat, obtuve {err:?}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("reset"),
        "el mensaje debería pedir `reset --yes`: {msg}"
    );
}

#[test]
fn test_resume_after_grouped_flush() {
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    write_synthetic_cifrado(&input_path);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1500));
        stop_clone.store(true, Ordering::SeqCst);
    });

    let opts1 = RunOptions {
        input_path: input_path.clone(),
        state_dir: state_dir.clone(),
        batch_size: 16 * 1024 * 1024,
        resume: false,
        force_resume: false,
        flush_every_n_batches: 4,
    };
    let sink1 = CountingSink::new();
    let outcome1 = runner::run(opts1, &sink1, stop).expect("run 1 limpio");
    assert!(
        matches!(outcome1, RunOutcome::Paused { .. }),
        "esperaba Paused, obtuve {outcome1:?}"
    );

    let progress_path = state_dir.join("progress.toml");
    let progress1 =
        load_progress_with_bak(&progress_path).expect("progress.toml legible tras pausa");
    let next1 = progress1.next_step;
    assert!(
        next1 >= (16u64 << 20) * 4,
        "tras 1.5 s y flush_every=4, deberíamos haber pasado al menos 1 flush \
         (≥ 4 batches), pero next_step = {next1}"
    );

    let stop2 = Arc::new(AtomicBool::new(false));
    let stop2_clone = Arc::clone(&stop2);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        stop2_clone.store(true, Ordering::SeqCst);
    });
    let opts2 = RunOptions {
        input_path,
        state_dir: state_dir.clone(),
        batch_size: 16 * 1024 * 1024,
        resume: true,
        force_resume: false,
        flush_every_n_batches: 8,
    };
    let sink2 = CountingSink::new();
    let outcome2 = runner::run(opts2, &sink2, stop2).expect("run 2 (resume) limpio");
    assert!(
        matches!(outcome2, RunOutcome::Paused { .. }),
        "esperaba Paused, obtuve {outcome2:?}"
    );

    let progress2 =
        load_progress_with_bak(&progress_path).expect("progress.toml legible tras resume");
    assert!(
        progress2.next_step >= next1,
        "monotonía rota: next_step regresó de {next1} a {}",
        progress2.next_step
    );
}

#[test]
fn test_save_load_roundtrip_after_d026() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("progress.toml");

    let mut progress = Progress::new();
    progress.next_step = 12345;
    progress.last_flush_utc = "2026-05-06T18:00:00Z".into();

    save_progress_with_bak(&path, &progress).unwrap();
    progress.next_step = 67890;
    save_progress_with_bak(&path, &progress).unwrap();

    let loaded = load_progress_with_bak(&path).unwrap();
    assert_eq!(loaded.next_step, 67890);
    assert_eq!(loaded.last_flush_utc, "2026-05-06T18:00:00Z");

    let bak = path.with_extension("toml.bak");
    assert!(bak.exists(), "bak debería existir tras 2 flushes");
    let bak_loaded = load_progress_with_bak(&bak).unwrap();
    assert_eq!(bak_loaded.next_step, 12345);
}
