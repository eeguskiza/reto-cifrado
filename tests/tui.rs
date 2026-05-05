//! Tests Fase 5 — TUI desacoplada del runner.

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::config::{ConfigEntry, IvSource, Kdf};
use quattro_crack::kdf::derive;
use quattro_crack::reference::{encrypt_cbc_pkcs7, KNOWN_PREFIX_32};
use quattro_crack::runner::{ProgressEvent, ProgressSink, StderrSink};
use quattro_crack::tui::{TuiSink, TuiSinkConfig};

const QC_BIN: &str = env!("CARGO_BIN_EXE_quattro-crack");

fn build_pt_1584() -> Vec<u8> {
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
    std::fs::write(path, STANDARD.encode(&bin)).unwrap();
}

#[test]
fn test_stderr_sink_emits_same_format_as_phase4() {
    // Setup: target_idx muy bajo para que el run termine rápido.
    let pw = b".aAaabbbb1000.";
    let key = derive(Kdf::Md5Utf8, pw);
    let iv = [0u8; 16];
    let pt = build_pt_1584();
    let ct = encrypt_cbc_pkcs7(key.as_slice(), &iv, &pt).unwrap();

    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    let log_dir = tmp.path().join("logs");
    write_cifrado(&input_path, &iv, &ct);

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
            "--preset",
            "canonical",
            "--batch-size",
            "1000000",
        ])
        .output()
        .expect("spawn run --no-tui");
    assert!(output.status.success(), "run debería terminar limpio: {output:?}");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Patrones clave que Fase 4 emitía y que --no-tui debe seguir emitiendo.
    assert!(stderr.contains("device:"), "header device: ausente:\n{stderr}");
    assert!(stderr.contains("plan:"), "header plan: ausente");
    assert!(
        stderr.contains("[cfg 1/4]") && stderr.contains("md5_utf8/cbc/first16"),
        "config-start pattern ausente:\n{stderr}"
    );
    assert!(
        stderr.contains("HIT CONFIRMADO") || stderr.contains("plan completado"),
        "ni HIT ni completion pattern:\n{stderr}"
    );

    // Verificación adicional: el log de tracing existe.
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

/// Buffer-writer sink para verificar formato sin spawnear subproceso.
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
fn test_progress_event_serialization() {
    // Cada variante puede construirse y debug-imprimirse.
    let events: Vec<ProgressEvent> = vec![
        ProgressEvent::PlanLoaded {
            total_configs: 4,
            total_candidates: 1_000_000,
            source_sha256: "deadbeef".into(),
            preset_name: Some("canonical".into()),
            batch_size: 1024,
            device_name: "GPU".into(),
        },
        ProgressEvent::Resumed {
            config_idx: 0,
            from_step: 100,
        },
        ProgressEvent::ResumeRejected {
            reason: "x".into(),
        },
        ProgressEvent::ConfigStarted {
            idx: 0,
            total: 4,
            kdf: "md5_utf8".into(),
            iv: "first16".into(),
            klen: 16,
            start_step: 0,
        },
        ProgressEvent::BatchCompleted {
            config_idx: 0,
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
        ProgressEvent::GpuMetricsUnavailable {
            reason: "test".into(),
        },
        ProgressEvent::HitConfirmed {
            config_idx: 0,
            kdf: "md5_utf8".into(),
            password: "x".into(),
            idx: 1,
            plaintext_hex_first_32: "ab".into(),
            elapsed_total: Duration::from_secs(1),
        },
        ProgressEvent::HitDiscardedPrefixMismatch {
            config_idx: 0,
            idx: 1,
        },
        ProgressEvent::HitCriticalPkcs7Mismatch {
            config_idx: 0,
            idx: 1,
            password: "x".into(),
        },
        ProgressEvent::Paused {
            config_idx: 0,
            last_step: 1,
            elapsed_total: Duration::from_secs(1),
        },
        ProgressEvent::ConfigCompleted {
            idx: 0,
            candidates_processed: 1,
            duration: Duration::from_secs(1),
            hits: 0,
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

    // Bonus: StderrSink puede consumirlos sin panic.
    let out = capture_with_stderr_sink(&events);
    assert!(out.contains("device:") && out.contains("[cfg 1/4]"));
}

#[test]
fn test_tui_sink_does_not_panic_on_missing_nvml() {
    // TuiSink no llama a NVML directamente — eso lo hace GpuMonitor.
    // Simulamos NVML missing recibiendo GpuMetricsUnavailable y verificamos
    // que el renderer lo procesa y termina limpio tras PlanCompleted.
    let mut sink = TuiSink::new(TuiSinkConfig {
        n_total_candidates: 1_000_000,
        project_version: "0.1.0".into(),
    });

    sink.on_event(ProgressEvent::GpuMetricsUnavailable {
        reason: "Nvml::init falló: test".into(),
    });
    sink.on_event(ProgressEvent::PlanLoaded {
        total_configs: 1,
        total_candidates: 1_000_000,
        source_sha256: "00".into(),
        preset_name: Some("canonical".into()),
        batch_size: 1024,
        device_name: "test".into(),
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
        project_version: "0.1.0".into(),
    });
    sink.on_event(ProgressEvent::PlanLoaded {
        total_configs: 1,
        total_candidates: 1_000_000,
        source_sha256: "00".into(),
        preset_name: None,
        batch_size: 1,
        device_name: "test".into(),
    });
    sink.on_event(ProgressEvent::PlanCompleted {
        total_hits: 0,
        elapsed_total: Duration::from_secs(0),
    });
    assert!(sink.wait_until_done(Duration::from_secs(2)));

    // Y para el path de Paused también.
    let mut sink2 = TuiSink::new(TuiSinkConfig {
        n_total_candidates: 1_000_000,
        project_version: "0.1.0".into(),
    });
    sink2.on_event(ProgressEvent::Paused {
        config_idx: 0,
        last_step: 100,
        elapsed_total: Duration::from_secs(1),
    });
    assert!(sink2.wait_until_done(Duration::from_secs(2)));
}

/// Fixture mínimo para asegurar que el bundle cfg-typed sigue construyéndose
/// — pillamos regresiones del `ConfigEntry` sin spawnear runner.
#[test]
fn test_config_entry_construction_smoke() {
    let c = ConfigEntry::new(Kdf::Md5Utf8, IvSource::First16);
    assert_eq!(c.kdf, Kdf::Md5Utf8);
    assert_eq!(c.iv, IvSource::First16);
}
