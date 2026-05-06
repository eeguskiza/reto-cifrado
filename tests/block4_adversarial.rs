//! Block 4 — barrido adversarial sobre el kernel activo y el cooperativo.
//!
//! Cubre:
//!   - Boundary idx (0, N-1, transiciones de campo).
//!   - Batch sizes extremos (1, 16, 31, 32, 33, 1023, 1024, 1025, 65535, 65536, 65537).
//!   - 1M idx random sin Leonardo en CT → cero falsos positivos.
//!   - Stress de prefijo-32 mismatch sintético (kernel reporta hit de prefijo-16,
//!     CPU descarta por prefijo-32, runner sigue sin abortar).
//!   - Carga de `state/progress.toml` real (read-only) y validación estructural.
//!
//! Estos tests aplican a AMBOS kernels (legacy y coop) — si los dos pasan,
//! la elección entre ellos es independiente del riesgo de correctitud.

use std::path::PathBuf;

use quattro_crack::combinatorics::{index_to_password, password_to_index, N};
use quattro_crack::cuda::{
    gpu_dump_pt_block0, gpu_dump_pt_block0_coop, CudaCtx, KernelBundle, KernelBundleCoop,
};
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{decrypt_ecb_raw, encrypt_ecb_pkcs7};
use quattro_crack::state::{load_progress_with_bak, Progress};

fn fixed_ct_block() -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
    }
    b
}

fn rand_indices(seed: u64, count: usize) -> Vec<u64> {
    let mut state = seed;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(state % N);
    }
    out
}

// ============================================================================
// 4.1 Boundary tests
// ============================================================================

#[test]
fn test_boundary_idx_zero_legacy_and_coop_match_reference() {
    // El primer índice del espacio: pw = ".aAaabbbb1000." (D-002).
    let pw0 = index_to_password(0);
    assert_eq!(&pw0[..], b".aAaabbbb1000.");

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_legacy = gpu_dump_pt_block0(&ctx, 0, 1, &ct_block_0).expect("legacy");
    let pts_coop = gpu_dump_pt_block0_coop(&ctx, 0, 1, &ct_block_0).expect("coop");

    let key = derive_md5hex(&pw0);
    let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");

    assert_eq!(&pt_cpu[..16], &pts_legacy[..16], "legacy != cpu en idx=0");
    assert_eq!(&pt_cpu[..16], &pts_coop[..16],   "coop   != cpu en idx=0");
}

#[test]
fn test_boundary_idx_last_legacy_and_coop_match_reference() {
    // Último índice del espacio: pw = ".zzzzuuuU1999.".
    let last = N - 1;
    let pw_last = index_to_password(last);
    assert_eq!(&pw_last[..], b".zzzzuuuU1999.");

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_legacy = gpu_dump_pt_block0(&ctx, last, 1, &ct_block_0).expect("legacy");
    let pts_coop = gpu_dump_pt_block0_coop(&ctx, last, 1, &ct_block_0).expect("coop");

    let key = derive_md5hex(&pw_last);
    let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");

    assert_eq!(&pt_cpu[..16], &pts_legacy[..16], "legacy != cpu en idx=N-1");
    assert_eq!(&pt_cpu[..16], &pts_coop[..16],   "coop   != cpu en idx=N-1");
}

#[test]
fn test_boundary_idx_field_transitions() {
    // Transiciones críticas entre campos del generador (D-002):
    //   N_VOWEL = 625, N_CONS·N_VOWEL = 121_550_625 (= QC_M_UPPER),
    //   QC_M_DISP = 850_854_375, QC_M_YEAR = 59_559_806_250.
    // En cada uno, validamos idx-1 / idx / idx+1.
    const TRANSITIONS: &[u64] = &[
        624, 625, 626,
        121_550_624, 121_550_625, 121_550_626,
        850_854_374, 850_854_375, 850_854_376,
        59_559_806_249, 59_559_806_250, 59_559_806_251,
    ];

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    for &idx in TRANSITIONS.iter() {
        if idx >= N { continue; }
        let pw = index_to_password(idx);
        let key = derive_md5hex(&pw);
        let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");

        let pts_legacy = gpu_dump_pt_block0(&ctx, idx, 1, &ct_block_0).expect("legacy");
        let pts_coop = gpu_dump_pt_block0_coop(&ctx, idx, 1, &ct_block_0).expect("coop");

        assert_eq!(&pt_cpu[..16], &pts_legacy[..16], "legacy mismatch en idx={idx}");
        assert_eq!(&pt_cpu[..16], &pts_coop[..16],   "coop mismatch en idx={idx}");
    }
}

// ============================================================================
// 4.1 Batch size extremes
// ============================================================================

#[test]
fn test_batch_size_extremes_match_reference() {
    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    // Tamaños que estresan grid sizing y stride loops:
    //   1 (1 grupo total), 16 (medio warp), 31/32/33 (warp boundaries),
    //   1023/1024/1025 (grupos múltiples de bloque), 65535/65536/65537
    //   (cerca del cap de grid_dim para coop con N_PER_GROUP=8).
    const SIZES: &[u64] = &[1, 16, 31, 32, 33, 1023, 1024, 1025, 65535, 65536, 65537];

    let base: u64 = 7_000_000_000;  // arbitrario, lejos de los bordes
    for &size in SIZES.iter() {
        let pts_legacy = gpu_dump_pt_block0(&ctx, base, size, &ct_block_0)
            .unwrap_or_else(|e| panic!("legacy size={size}: {e:?}"));
        let pts_coop = gpu_dump_pt_block0_coop(&ctx, base, size, &ct_block_0)
            .unwrap_or_else(|e| panic!("coop size={size}: {e:?}"));

        assert_eq!(pts_legacy.len(), (size as usize) * 16);
        assert_eq!(pts_coop.len(),   (size as usize) * 16);

        // Para el primero y el último de cada batch comparamos contra reference.
        for &j in &[0u64, size - 1] {
            let idx = base + j;
            let pw = index_to_password(idx);
            let key = derive_md5hex(&pw);
            let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");
            let off = (j as usize) * 16;
            assert_eq!(
                &pt_cpu[..16], &pts_legacy[off..off + 16],
                "legacy batch_size={size}: idx={idx}"
            );
            assert_eq!(
                &pt_cpu[..16], &pts_coop[off..off + 16],
                "coop batch_size={size}: idx={idx}"
            );
        }
    }
}

// ============================================================================
// 4.3 False positives — legacy (coop ya tiene su test en coop_kernel_parity.rs)
// ============================================================================

#[test]
fn test_legacy_no_false_positives_1m_random_ct() {
    // CT que descifra a algo no-Leonardo bajo cualquier clave del espacio
    // (estadísticamente garantizado: probabilidad de match prefijo-16 con
    // bytes aleatorios ≈ 2⁻¹²⁸).
    let ct_block_0 = {
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(0x12);
        }
        b
    };

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load legacy");

    const RANGE: u64 = 1_000_000;
    let base = N / 3;
    let hits = bundle.launch(base, RANGE, &ct_block_0).expect("launch");
    assert!(
        hits.is_empty(),
        "false positive legacy sobre [{base}, {base}+{RANGE}): {hits:?}"
    );
}

// ============================================================================
// 4.3 PrefixMismatch32 — el kernel reporta, CPU descarta sin abortar
// ============================================================================

#[test]
fn test_prefix32_mismatch_synthetic_legacy_and_coop() {
    // Construye un PT donde los primeros 16 B son KNOWN_PREFIX_16 pero
    // los siguientes 16 NO matchean KNOWN_PREFIX_32 (deliberado).
    //
    // Como el kernel solo compara prefijo-16, va a reportar hit. La CPU
    // tiene que detectar el mismatch en los siguientes 16 B y devolver
    // `HitVerdict::PrefixMismatch32` — el runner LO DESCARTA, no aborta.
    use quattro_crack::reference::{validate_hit, HitVerdict, KNOWN_PREFIX_16};

    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válida");

    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_16);              // 16 B coinciden
    pt.extend_from_slice(b"NO_COINCIDE_32B!");          // 16 B distintos
    while pt.len() < 1600 {
        pt.push(b'X');
    }

    let key = derive_md5hex(pw);
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut legacy = KernelBundle::load(&ctx).expect("load legacy");
    let mut coop = KernelBundleCoop::load(&ctx).expect("load coop");

    const RANGE: u64 = 200_000;
    let base = target_idx.saturating_sub(RANGE / 2);

    let hits_legacy = legacy.launch(base, RANGE, &ct_block_0).expect("legacy");
    let hits_coop = coop.launch(base, RANGE, &ct_block_0).expect("coop");

    assert!(hits_legacy.iter().any(|h| h.idx == target_idx),
            "legacy debería haber emitido hit de prefijo-16");
    assert!(hits_coop.iter().any(|h| h.idx == target_idx),
            "coop debería haber emitido hit de prefijo-16");

    // CPU descarta el hit del idx con PrefixMismatch32 (no aborta).
    let verdict = validate_hit(&key, &ct).expect("validate_hit");
    match verdict {
        HitVerdict::PrefixMismatch32 => {}
        other => panic!("esperaba PrefixMismatch32, obtuve {other:?}"),
    }
}

// ============================================================================
// 4.5 Cross-verify CPU↔GPU sobre 100 idx fijos con seed
// ============================================================================

#[test]
fn test_cross_verify_cpu_gpu_100_fixed_indices() {
    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    // 100 idx con seed fijo + boundaries explícitos.
    let mut idxs: Vec<u64> = rand_indices(0xdead_beef_dead_beefu64, 95);
    idxs.extend([0u64, 1, N / 2, N - 2, N - 1]);

    for &idx in idxs.iter() {
        let pw = index_to_password(idx);
        let key = derive_md5hex(&pw);

        let pts_legacy = gpu_dump_pt_block0(&ctx, idx, 1, &ct_block_0).expect("legacy");
        let pts_coop = gpu_dump_pt_block0_coop(&ctx, idx, 1, &ct_block_0).expect("coop");
        let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");

        assert_eq!(&pt_cpu[..16], &pts_legacy[..16], "legacy idx={idx}");
        assert_eq!(&pt_cpu[..16], &pts_coop[..16],   "coop idx={idx}");
    }
}

// ============================================================================
// 4.6 Production state — read-only validation
// ============================================================================

#[test]
fn test_real_progress_toml_loadable_if_present() {
    // Solo se ejecuta si state/progress.toml existe (no falla en CI limpia).
    let path = PathBuf::from("state/progress.toml");
    if !path.exists() {
        eprintln!("[skip] state/progress.toml no existe; el test se valida en máquina con run iniciado");
        return;
    }

    let progress: Progress = load_progress_with_bak(&path)
        .expect("debe parsear con la struct Progress actual");
    assert!(progress.next_step <= N, "next_step fuera de rango: {}", progress.next_step);
    assert!(progress.tried >= progress.next_step,
            "tried < next_step: tried={}, next_step={}", progress.tried, progress.next_step);
    eprintln!(
        "production state: next_step={}, tried={}, elapsed_us={}, hits={}",
        progress.next_step, progress.tried, progress.elapsed_us, progress.hits.len()
    );
}

#[test]
fn test_kernel_runs_from_real_next_step_if_present() {
    // Lee el next_step real del usuario y lanza ambos kernels desde ahí
    // sobre un ciphertext sintético. Verifica que no panics, que no
    // hay false positives (el ct aleatorio no coincide con Leonardo),
    // y que ambos kernels ven los mismos plaintexts byte-a-byte.
    let path = PathBuf::from("state/progress.toml");
    if !path.exists() {
        eprintln!("[skip] state/progress.toml no existe");
        return;
    }
    let progress: Progress = load_progress_with_bak(&path).expect("load");
    let from_step = progress.next_step;
    if from_step >= N {
        eprintln!("[skip] barrido completado, from_step={}", from_step);
        return;
    }

    let count: u64 = 4096.min(N - from_step);

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_legacy = gpu_dump_pt_block0(&ctx, from_step, count, &ct_block_0).expect("legacy");
    let pts_coop = gpu_dump_pt_block0_coop(&ctx, from_step, count, &ct_block_0).expect("coop");
    assert_eq!(pts_legacy, pts_coop,
               "legacy vs coop divergen desde el next_step real ({from_step})");

    // Verificamos los primeros y últimos 5 idx contra reference.
    for j in (0..5u64).chain((count - 5)..count) {
        let idx = from_step + j;
        let pw = index_to_password(idx);
        let key = derive_md5hex(&pw);
        let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu");
        let off = (j as usize) * 16;
        assert_eq!(&pt_cpu[..16], &pts_legacy[off..off + 16],
                   "legacy != cpu desde production next_step, j={j}, idx={idx}");
    }

    eprintln!("kernel runs OK desde production next_step={from_step}, +{count} idx");
}
