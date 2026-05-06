//! Tests Fase 5 + adaptados a D-029.

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{encrypt_ecb_pkcs7, KNOWN_PREFIX_32};
use quattro_crack::runner::{ProgressEvent, ProgressSink, StderrSink};
use quattro_crack::tui::{TuiSink, TuiSinkConfig};

const QC_BIN: &str = env!("CARGO_BIN_EXE_quattro-crack");

fn build_pt_1600() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }
    pt
}

fn write_cifrado_ecb(path: &Path, ct_1616: &[u8]) {
    assert_eq!(ct_1616.len(), 1616);
    std::fs::write(path, STANDARD.encode(ct_1616)).unwrap();
}

#[test]
fn test_stderr_sink_emits_phase4_compatible_format() {
    // Setup: target_idx muy bajo para que el run termine rápido.
    let pw = b".aAaabbbb1000.";
    let key = derive_md5hex(pw);
    let pt = build_pt_1600();
    let ct = encrypt_ecb_pkcs7(&key, &pt);

    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    let log_dir = tmp.path().join("logs");
    write_cifrado_ecb(&input_path, &ct);

    let output = Command::new(QC_BIN)
        .args([
            "run",
            "--no-tui",
            "--input",
            input_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--log-dir",
            log_dir.to_str().unwrap(),
            "--batch-size",
            "1000000",
            "--flush-every",
            "1",
        ])
        .output()
        .expect("spawn run --no-tui");
    assert!(output.status.success(), "run debería terminar limpio: {output:?}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("device:"), "header device: ausente:\n{stderr}");
    assert!(stderr.contains("plan:"), "header plan: ausente");
    assert!(
        stderr.contains("md5hex_full"),
        "no aparece la única config (md5hex_full):\n{stderr}"
    );
    assert!(
        stderr.contains("HIT CONFIRMADO") || stderr.contains("plan completado"),
        "ni HIT ni completion pattern:\n{stderr}"
    );

    let logs: Vec<_> = std::fs::read_dir(&log_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert!(
        !logs.is_empty(),
        "tracing debería haber creado un fichero en {}",
        log_dir.display()
    );
}

fn capture_with_stderr_sink(events: &[ProgressEvent]) -> String {
    struct W(Arc<Mutex<Vec<u8>>>);
    impl Write for W {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = StderrSink::from_writer(W(Arc::clone(&buf)));
    for e in events {
        sink.on_event(e.clone());
    }
    let v = buf.lock().unwrap().clone();
    String::from_utf8_lossy(&v).into_owned()
}

#[test]
fn test_progress_events_serialize_after_d029() {
    let events: Vec<ProgressEvent> = vec![
        ProgressEvent::PlanLoaded {
            total_candidates: 1_000_000,
            source_sha256: "deadbeef".into(),
            batch_size: 1024,
            device_name: "GPU".into(),
            config_id: "md5hex_full / aes-256-ecb / pkcs7".into(),
        },
        ProgressEvent::Resumed { from_step: 100 },
        ProgressEvent::ResumeRejected { reason: "x".into() },
        ProgressEvent::BatchCompleted {
            batch_num: 10,
            current_step: 1000,
            candidates_in_batch: 100,
            batch_duration_ms: 5,
        },
        ProgressEvent::GpuSample {
            utilization_pct: 50,
            memory_used_mb: 1024,
            memory_total_mb: 16384,
            temperature_c: 60,
            power_w: 200,
        },
        ProgressEvent::GpuMetricsUnavailable { reason: "test".into() },
        ProgressEvent::HitConfirmed {
            password: "x".into(),
            idx: 1,
            plaintext_hex_first_32: "ab".into(),
            elapsed_total: Duration::from_secs(1),
        },
        ProgressEvent::HitDiscardedPrefixMismatch { idx: 1 },
        ProgressEvent::HitCriticalPkcs7Mismatch {
            idx: 1,
            password: "x".into(),
        },
        ProgressEvent::Paused {
            last_step: 1,
            elapsed_total: Duration::from_secs(1),
        },
        ProgressEvent::PlanCompleted {
            total_hits: 0,
            elapsed_total: Duration::from_secs(1),
        },
    ];
    for e in &events {
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
    }

    let out = capture_with_stderr_sink(&events);
    assert!(out.contains("device:"));
    assert!(out.contains("md5hex_full"));
}

#[test]
fn test_tui_sink_does_not_panic_on_missing_nvml() {
    let mut sink = TuiSink::new(TuiSinkConfig {
        n_total_candidates: 1_000_000,
        project_version: "0.2.0".into(),
    });
    sink.on_event(ProgressEvent::GpuMetricsUnavailable {
        reason: "Nvml::init falló: test".into(),
    });
    sink.on_event(ProgressEvent::PlanLoaded {
        total_candidates: 1_000_000,
        source_sha256: "00".into(),
        batch_size: 1024,
        device_name: "test".into(),
        config_id: "md5hex_full / aes-256-ecb / pkcs7".into(),
    });
    sink.on_event(ProgressEvent::PlanCompleted {
        total_hits: 0,
        elapsed_total: Duration::from_secs(0),
    });
    assert!(
        sink.wait_until_done(Duration::from_secs(2)),
        "renderer debería terminar tras PlanCompleted"
    );
}

#[test]
fn test_tui_completes_on_plan_completed_event() {
    let mut sink = TuiSink::new(TuiSinkConfig {
        n_total_candidates: 1_000_000,
        project_version: "0.2.0".into(),
    });
    sink.on_event(ProgressEvent::PlanLoaded {
        total_candidates: 1_000_000,
        source_sha256: "00".into(),
        batch_size: 1,
        device_name: "test".into(),
        config_id: "md5hex_full / aes-256-ecb / pkcs7".into(),
    });
    sink.on_event(ProgressEvent::PlanCompleted {
        total_hits: 0,
        elapsed_total: Duration::from_secs(0),
    });
    assert!(sink.wait_until_done(Duration::from_secs(2)));

    let mut sink2 = TuiSink::new(TuiSinkConfig {
        n_total_candidates: 1_000_000,
        project_version: "0.2.0".into(),
    });
    sink2.on_event(ProgressEvent::Paused {
        last_step: 100,
        elapsed_total: Duration::from_secs(1),
    });
    assert!(sink2.wait_until_done(Duration::from_secs(2)));
}
