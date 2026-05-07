//! D-034 — Tests que blindan la corrección del prefijo-32 (doble CRLF)
//! y la nueva observabilidad de descartes `PrefixMismatch32`.
//!
//! El barrido del 2026-05-07 (8 h, 100 % del espacio) terminó sin hit
//! confirmado porque `KNOWN_PREFIX_32` tenía un único CRLF entre los
//! dos "Leonardo da Vinci". El layout real de la pizarra es doble CRLF
//! (línea en blanco intermedia). Estos tests blindan:
//!
//!  - el layout binario exacto de la constante;
//!  - que el barrido sintético (kernel + CPU) confirma un hit con un
//!    plaintext que arranca por doble CRLF;
//!  - que los nuevos contadores `prefix32_mismatch_*` se persisten en
//!    `progress.toml` y que un TOML viejo sin esos campos sigue
//!    cargándose con valores por defecto.

use std::time::Instant;

use quattro_crack::combinatorics::{password_to_index, N};
use quattro_crack::cuda::{CudaCtx, KernelBundle};
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{
    encrypt_ecb_pkcs7, validate_hit, HitVerdict, KNOWN_PREFIX_16, KNOWN_PREFIX_32,
};
use quattro_crack::state::{load_progress, save_progress, Progress};
use tempfile::TempDir;

// ============================================================================
// 1. Layout exacto del prefijo-32 corregido
// ============================================================================

#[test]
fn known_prefix_32_has_double_crlf() {
    assert_eq!(KNOWN_PREFIX_32.len(), 32);
    assert_eq!(&KNOWN_PREFIX_32[..17], b"Leonardo da Vinci");
    assert_eq!(&KNOWN_PREFIX_32[17..21], b"\r\n\r\n", "doble CRLF requerido");
    assert_eq!(&KNOWN_PREFIX_32[21..32], b"Leonardo da");
    // Sanity: el prefijo-16 sigue siendo el subprefijo del 32.
    assert_eq!(&KNOWN_PREFIX_32[..16], KNOWN_PREFIX_16);
    // Sanity defensiva contra una regresión al CRLF único.
    assert_ne!(KNOWN_PREFIX_32, b"Leonardo da Vinci\r\nLeonardo da V");
}

// ============================================================================
// 2. End-to-end sintético con doble CRLF: el barrido encuentra el hit
//    y `validate_hit` devuelve `Confirmed`, NO `PrefixMismatch32`.
// ============================================================================

#[test]
fn e2e_double_crlf_plaintext_finds_hit_confirmed() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válida del espacio");
    eprintln!("target idx = {target_idx} (de N = {N})");

    // Construye un plaintext de 1600 B que arranca con el prefijo real
    // (doble CRLF) y rellena con 'X' hasta cubrir 100 bloques.
    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }

    let key = derive_md5hex(pw);
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    assert_eq!(ct.len(), 1616);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load kernel ECB md5hex");

    const RANGE: u64 = 200_000;
    let idx_base = target_idx.saturating_sub(RANGE / 2);

    let started = Instant::now();
    let hits = bundle.launch(idx_base, RANGE, &ct_block_0).expect("launch");
    eprintln!(
        "kernel emitió {} hit(s) en {:?}",
        hits.len(),
        started.elapsed()
    );

    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "el kernel debería haber emitido prefijo-16 para target_idx={target_idx}"
    );

    // CPU: con doble CRLF, validate_hit debe devolver Confirmed.
    match validate_hit(&key, &ct).expect("validate_hit") {
        HitVerdict::Confirmed { plaintext } => {
            assert!(plaintext.starts_with(KNOWN_PREFIX_32));
        }
        HitVerdict::PrefixMismatch32 { plaintext_first_32 } => panic!(
            "REGRESIÓN D-034: validate_hit devolvió PrefixMismatch32 \
             con plaintext_first_32={}",
            hex::encode(plaintext_first_32)
        ),
        other => panic!("esperaba Confirmed, obtuve {other:?}"),
    }
}

// ============================================================================
// 3. Persistencia round-trip de los contadores nuevos en TOML
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
// 4. Compatibilidad backward: un progress.toml viejo (pre-D-034, sin
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
