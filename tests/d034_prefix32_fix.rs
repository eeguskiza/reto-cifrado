//! D-034 (vigente bajo D-035) — observabilidad de descartes
//! `PrefixMismatch32` y persistencia de contadores en `progress.toml`.
//!
//! Tras D-035 hay DOS variantes válidas del prefijo-32 (LF y CRLF). Si
//! el kernel emite un hit (prefijo-16 OK) pero CPU no matchea ni LF ni
//! CRLF, se cuenta como descarte y se persiste en el TOML.

use quattro_crack::combinatorics::password_to_index;
use quattro_crack::cuda::{CudaCtx, KernelBundle};
use quattro_crack::reference::{
    build_key_passraw, encrypt_cifraronline, validate_hit, HitVerdict, LineEnding, KNOWN_PREFIX_16,
    KNOWN_PREFIX_32_CRLF, KNOWN_PREFIX_32_LF,
};
use quattro_crack::state::{load_progress, save_progress, Progress};
use tempfile::TempDir;

// ============================================================================
// 1. Layout exacto de los dos prefijos-32 (LF y CRLF).
// ============================================================================

#[test]
fn known_prefix_32_lf_layout() {
    assert_eq!(KNOWN_PREFIX_32_LF.len(), 32);
    assert_eq!(&KNOWN_PREFIX_32_LF[..17], b"Leonardo da Vinci");
    assert_eq!(&KNOWN_PREFIX_32_LF[17..19], b"\n\n", "LF simple requerido");
    assert_eq!(&KNOWN_PREFIX_32_LF[19..32], b"Leonardo da V");
    assert_eq!(&KNOWN_PREFIX_32_LF[..16], KNOWN_PREFIX_16);
}

#[test]
fn known_prefix_32_crlf_layout() {
    assert_eq!(KNOWN_PREFIX_32_CRLF.len(), 32);
    assert_eq!(&KNOWN_PREFIX_32_CRLF[..17], b"Leonardo da Vinci");
    assert_eq!(&KNOWN_PREFIX_32_CRLF[17..21], b"\r\n\r\n", "CRLF requerido");
    assert_eq!(&KNOWN_PREFIX_32_CRLF[21..32], b"Leonardo da");
    assert_eq!(&KNOWN_PREFIX_32_CRLF[..16], KNOWN_PREFIX_16);
}

// ============================================================================
// 2. End-to-end con LF: el barrido encuentra hit y `validate_hit`
//    devuelve `Confirmed { line_ending: Lf }`, NO PrefixMismatch32.
// ============================================================================

#[test]
fn e2e_lf_plaintext_finds_hit_confirmed() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válido");

    let mut pt = Vec::new();
    pt.extend_from_slice(KNOWN_PREFIX_32_LF);
    pt.extend_from_slice(b" rest of LF synthetic plaintext.");

    let key = build_key_passraw(pw);
    let ct = encrypt_cifraronline(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load");

    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch");

    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel debería emitir hit prefijo-16 para target_idx={target_idx}"
    );

    match validate_hit(&key, &ct).expect("validate_hit") {
        HitVerdict::Confirmed { line_ending, .. } => {
            assert_eq!(line_ending, LineEnding::Lf);
        }
        other => panic!("REGRESIÓN D-035: esperaba Confirmed (LF), obtuve {other:?}"),
    }
}

// ============================================================================
// 3. End-to-end con CRLF: idem.
// ============================================================================

#[test]
fn e2e_crlf_plaintext_finds_hit_confirmed() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válido");

    let mut pt = Vec::new();
    pt.extend_from_slice(KNOWN_PREFIX_32_CRLF);
    pt.extend_from_slice(b" rest of CRLF synthetic plaintext.");

    let key = build_key_passraw(pw);
    let ct = encrypt_cifraronline(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load");

    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch");

    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel debería emitir hit prefijo-16 para target_idx={target_idx}"
    );

    match validate_hit(&key, &ct).expect("validate_hit") {
        HitVerdict::Confirmed { line_ending, .. } => {
            assert_eq!(line_ending, LineEnding::Crlf);
        }
        other => panic!("REGRESIÓN D-035: esperaba Confirmed (CRLF), obtuve {other:?}"),
    }
}

// ============================================================================
// 4. Persistencia round-trip de los contadores en TOML.
// ============================================================================

#[test]
fn progress_persists_prefix32_counters() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("progress.toml");

    let mut p = Progress::new();
    p.next_step = 12_345;
    p.tried = 12_345;
    p.prefix32_mismatch_count = 5;
    p.prefix32_mismatch_idx_samples = vec![100, 200, 300];
    save_progress(&path, &p).unwrap();

    let loaded = load_progress(&path).unwrap();
    assert_eq!(loaded.prefix32_mismatch_count, 5);
    assert_eq!(loaded.prefix32_mismatch_idx_samples, vec![100, 200, 300]);
    assert_eq!(loaded.next_step, 12_345);
}

// ============================================================================
// 5. Compatibilidad backward: un progress.toml viejo (pre-D-034, sin
//    los campos nuevos) carga con `count = 0` y `samples = []`.
// ============================================================================

#[test]
fn legacy_progress_without_prefix32_fields_loads_with_defaults() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("progress.toml");

    let legacy = r#"
next_step = 59559806250000
tried = 59559806250000
elapsed_us = 33935359941
hits = []
last_flush_utc = "2026-05-07T14:56:41.549988035+00:00"
"#;
    std::fs::write(&path, legacy).unwrap();

    let loaded = load_progress(&path).expect("debe cargar TOML viejo sin campos nuevos");
    assert_eq!(loaded.next_step, 59_559_806_250_000);
    assert_eq!(loaded.tried, 59_559_806_250_000);
    assert_eq!(
        loaded.prefix32_mismatch_count, 0,
        "campo ausente debe defaultear a 0"
    );
    assert!(
        loaded.prefix32_mismatch_idx_samples.is_empty(),
        "campo ausente debe defaultear a []"
    );
}
