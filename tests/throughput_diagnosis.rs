//! Diagnóstico Fase 7 + adaptado a D-035. Tests `#[ignore]` (CUDA + I/O
//! reales). Invocar con:
//!
//!     cargo test --release --test throughput_diagnosis -- \
//!         --ignored --nocapture --test-threads=1

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tempfile::TempDir;

use quattro_crack::ciphertext::TOTAL_BIN_LEN;
use quattro_crack::cuda::{CudaCtx, KernelBundle};
use quattro_crack::reference::{build_key_passraw, encrypt_cifraronline, KNOWN_PREFIX_32_LF};
use quattro_crack::runner::{self, ProgressEvent, ProgressSink, RunOptions, RunOutcome};
use quattro_crack::state::{save_progress_with_bak, Progress};

struct CountingSink {
    batches: std::sync::atomic::AtomicU64,
}

impl CountingSink {
    fn new() -> Self {
        Self {
            batches: std::sync::atomic::AtomicU64::new(0),
        }
    }
    fn batches(&self) -> u64 {
        self.batches.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ProgressSink for CountingSink {
    fn on_event(&self, event: ProgressEvent) {
        if matches!(event, ProgressEvent::BatchCompleted { .. }) {
            self.batches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

fn build_plaintext_for_1616() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1584);
    pt.extend_from_slice(KNOWN_PREFIX_32_LF);
    while pt.len() < 1584 {
        pt.push(b'X');
    }
    pt.truncate(1584);
    pt
}

fn write_synthetic_cifrado(path: &Path) {
    let pw = b".aAabbabb1999.";
    let key = build_key_passraw(pw);
    let pt = build_plaintext_for_1616();
    let ct = encrypt_cifraronline(&key, &pt);
    assert_eq!(ct.len(), TOTAL_BIN_LEN);
    let b64 = STANDARD.encode(&ct);
    std::fs::write(path, b64).unwrap();
}

#[test]
#[ignore]
fn diagnose_save_progress_overhead() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("progress.toml");
    let mut progress = Progress::new();
    progress.last_flush_utc = "2026-05-06T18:00:00Z".into();
    for _ in 0..3 {
        save_progress_with_bak(&path, &progress).unwrap();
    }
    const N: usize = 100;
    let started = Instant::now();
    for i in 0..N {
        progress.next_step = (i as u64) * 16_777_216;
        save_progress_with_bak(&path, &progress).unwrap();
    }
    let elapsed = started.elapsed();
    let per_call_ms = elapsed.as_secs_f64() * 1000.0 / (N as f64);
    eprintln!(
        "save_progress_with_bak  iters={N}  total={:?}  per_call={:.2} ms",
        elapsed, per_call_ms
    );
}

fn diagnose_kernel_only(batch_size: u64) {
    let ctx = CudaCtx::init().unwrap();
    let mut bundle = KernelBundle::load(&ctx).unwrap();
    let ct_block_0 = [0xffu8; 16];
    let _ = bundle
        .launch(0, batch_size.min(16 * 1024 * 1024), &ct_block_0)
        .unwrap();
    let mut total: u64 = 0;
    let started = Instant::now();
    let mut idx_base: u64 = 0;
    while started.elapsed() < Duration::from_secs(5) {
        let _ = bundle.launch(idx_base, batch_size, &ct_block_0).unwrap();
        total += batch_size;
        idx_base = idx_base.wrapping_add(batch_size);
    }
    let elapsed = started.elapsed();
    let ghs = total as f64 / elapsed.as_secs_f64() / 1.0e9;
    eprintln!(
        "kernel-only D-035  batch={:>4.0} Mi  total={:>12} cands  elapsed={:>6.2?}s  GH/s={:.3}",
        batch_size as f64 / (1u64 << 20) as f64,
        total,
        elapsed,
        ghs
    );
}

#[test]
#[ignore]
fn diagnose_kernel_only_5s_batch16mi() {
    diagnose_kernel_only(16 * 1024 * 1024);
}
#[test]
#[ignore]
fn diagnose_kernel_only_5s_batch32mi() {
    diagnose_kernel_only(32 * 1024 * 1024);
}
#[test]
#[ignore]
fn diagnose_kernel_only_5s_batch64mi() {
    diagnose_kernel_only(64 * 1024 * 1024);
}
#[test]
#[ignore]
fn diagnose_kernel_only_5s_batch128mi() {
    diagnose_kernel_only(128 * 1024 * 1024);
}

fn diagnose_runner_throughput(batch_size: u32, flush_every: u32, secs: u64) {
    let tmp = TempDir::new().unwrap();
    let input_path = tmp.path().join("cifrado.txt");
    let state_dir = tmp.path().join("state");
    write_synthetic_cifrado(&input_path);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(secs));
        stop_clone.store(true, Ordering::SeqCst);
    });

    let opts = RunOptions {
        input_path,
        state_dir,
        batch_size,
        resume: false,
        force_resume: false,
        flush_every_n_batches: flush_every,
    };

    let sink = CountingSink::new();
    let started = Instant::now();
    let outcome = runner::run(opts, &sink, stop).expect("runner debe terminar limpio");
    let elapsed = started.elapsed();

    let batches = sink.batches();
    let total = batches * batch_size as u64;
    let ghs = total as f64 / elapsed.as_secs_f64() / 1.0e9;
    eprintln!(
        "runner D-035  batch={:>4.0} Mi  flush={:>2}  batches={:>5}  total={:>12}  elapsed={:>6.2?}s  GH/s={:.3}  outcome={}",
        batch_size as f64 / (1u64 << 20) as f64,
        flush_every,
        batches,
        total,
        elapsed,
        ghs,
        match outcome {
            RunOutcome::Paused { .. } => "Paused",
            RunOutcome::Found { .. } => "Found",
            RunOutcome::Completed { .. } => "Completed",
        }
    );
}

#[test]
#[ignore]
fn diagnose_runner_5s_batch16mi_flush1() {
    diagnose_runner_throughput(16 * 1024 * 1024, 1, 5);
}
#[test]
#[ignore]
fn diagnose_runner_5s_batch16mi_flush8() {
    diagnose_runner_throughput(16 * 1024 * 1024, 8, 5);
}
#[test]
#[ignore]
fn diagnose_runner_5s_batch64mi_flush1() {
    diagnose_runner_throughput(64 * 1024 * 1024, 1, 5);
}
#[test]
#[ignore]
fn diagnose_runner_5s_batch64mi_flush8() {
    diagnose_runner_throughput(64 * 1024 * 1024, 8, 5);
}
#[test]
#[ignore]
fn diagnose_runner_5s_batch128mi_flush4() {
    diagnose_runner_throughput(128 * 1024 * 1024, 4, 5);
}
