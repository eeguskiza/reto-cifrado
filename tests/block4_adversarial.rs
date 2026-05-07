//! Block 4 — barrido adversarial sobre el kernel D-035 (passraw + AES-128).
//!
//! Cubre:
//!   - Boundary idx (0, N-1, transiciones de campo).
//!   - Batch sizes extremos (1, 16, 31, 32, 33, 1023, 1024, 1025, 65535, 65536, 65537).
//!   - 1M idx random sin Leonardo en CT → cero falsos positivos.
//!   - Stress de prefijo-32 mismatch sintético (kernel reporta hit de prefijo-16,
//!     CPU descarta porque ni LF ni CRLF matchean, runner sigue sin abortar).
//!   - Carga de `state/progress.toml` real (read-only) y validación estructural.
//!   - Lanzamiento del kernel desde el `next_step` real (read-only).

use std::path::PathBuf;

use quattro_crack::combinatorics::{index_to_password, password_to_index, N};
use quattro_crack::cuda::{gpu_dump_pt_block0, CudaCtx, KernelBundle};
use quattro_crack::reference::{
    build_key_passraw, decrypt_aes128_ecb_raw, encrypt_cifraronline, KNOWN_PREFIX_16,
};
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
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push(state % N);
    }
    out
}

// ============================================================================
// 4.1 Boundary tests
// ============================================================================

#[test]
fn test_boundary_idx_zero_kernel_matches_reference() {
    let pw0 = index_to_password(0);
    assert_eq!(&pw0[..], b".aAaabbbb1000.");

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_gpu = gpu_dump_pt_block0(&ctx, 0, 1, &ct_block_0).expect("gpu");

    let key = build_key_passraw(&pw0);
    let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");

    assert_eq!(&pt_cpu[..16], &pts_gpu[..16], "kernel != cpu en idx=0");
}

#[test]
fn test_boundary_idx_last_kernel_matches_reference() {
    let last = N - 1;
    let pw_last = index_to_password(last);
    assert_eq!(&pw_last[..], b".zzzzuuuU1999.");

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_gpu = gpu_dump_pt_block0(&ctx, last, 1, &ct_block_0).expect("gpu");

    let key = build_key_passraw(&pw_last);
    let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");

    assert_eq!(&pt_cpu[..16], &pts_gpu[..16], "kernel != cpu en idx=N-1");
}

#[test]
fn test_boundary_idx_field_transitions() {
    const TRANSITIONS: &[u64] = &[
        624,
        625,
        626,
        121_550_624,
        121_550_625,
        121_550_626,
        850_854_374,
        850_854_375,
        850_854_376,
        59_559_806_249,
        59_559_806_250,
        59_559_806_251,
    ];

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    for &idx in TRANSITIONS.iter() {
        if idx >= N {
            continue;
        }
        let pw = index_to_password(idx);
        let key = build_key_passraw(&pw);
        let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");

        let pts_gpu = gpu_dump_pt_block0(&ctx, idx, 1, &ct_block_0).expect("gpu");

        assert_eq!(
            &pt_cpu[..16],
            &pts_gpu[..16],
            "kernel mismatch en idx={idx}"
        );
    }
}

// ============================================================================
// 4.2 Batch size extremes
// ============================================================================

#[test]
fn test_batch_size_extremes_match_reference() {
    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    const SIZES: &[u64] = &[1, 16, 31, 32, 33, 1023, 1024, 1025, 65535, 65536, 65537];

    let base: u64 = 7_000_000_000;
    for &size in SIZES.iter() {
        let pts_gpu = gpu_dump_pt_block0(&ctx, base, size, &ct_block_0)
            .unwrap_or_else(|e| panic!("kernel size={size}: {e:?}"));

        assert_eq!(pts_gpu.len(), (size as usize) * 16);

        for &j in &[0u64, size - 1] {
            let idx = base + j;
            let pw = index_to_password(idx);
            let key = build_key_passraw(&pw);
            let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");
            let off = (j as usize) * 16;
            assert_eq!(
                &pt_cpu[..16],
                &pts_gpu[off..off + 16],
                "kernel batch_size={size}: idx={idx}"
            );
        }
    }
}

// ============================================================================
// 4.3 False positives — kernel D-035
// ============================================================================

#[test]
fn test_kernel_no_false_positives_1m_random_ct() {
    let ct_block_0 = {
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(0x12);
        }
        b
    };

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load D-035");

    const RANGE: u64 = 1_000_000;
    let base = N / 3;
    let hits = bundle.launch(base, RANGE, &ct_block_0).expect("launch");
    assert!(
        hits.is_empty(),
        "false positive D-035 sobre [{base}, {base}+{RANGE}): {hits:?}"
    );
}

// ============================================================================
// 4.4 PrefixMismatch32 — kernel reporta, CPU descarta sin abortar
// ============================================================================

#[test]
fn test_prefix32_mismatch_synthetic_kernel_d035() {
    use quattro_crack::reference::{validate_hit, HitVerdict};

    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válido");

    // Plaintext con primeros 16 B = KNOWN_PREFIX_16 pero los siguientes
    // 16 NO matchean ni LF ni CRLF.
    let mut pt = Vec::new();
    pt.extend_from_slice(KNOWN_PREFIX_16);
    pt.extend_from_slice(b"NO_COINCIDE_32B!");
    pt.extend_from_slice(b" rest of the message body");

    let key = build_key_passraw(pw);
    let ct = encrypt_cifraronline(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load D-035");

    const RANGE: u64 = 200_000;
    let base = target_idx.saturating_sub(RANGE / 2);

    let hits = bundle.launch(base, RANGE, &ct_block_0).expect("launch");

    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel debería haber emitido hit de prefijo-16"
    );

    // CPU descarta el hit con PrefixMismatch32 (ni LF ni CRLF matchean).
    let verdict = validate_hit(&key, &ct).expect("validate_hit");
    match verdict {
        HitVerdict::PrefixMismatch32 { plaintext_first_32 } => {
            assert_eq!(&plaintext_first_32[..16], KNOWN_PREFIX_16);
            assert_eq!(&plaintext_first_32[16..32], b"NO_COINCIDE_32B!");
        }
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

    let mut idxs: Vec<u64> = rand_indices(0xdead_beef_dead_beefu64, 95);
    idxs.extend([0u64, 1, N / 2, N - 2, N - 1]);

    for &idx in idxs.iter() {
        let pw = index_to_password(idx);
        let key = build_key_passraw(&pw);

        let pts_gpu = gpu_dump_pt_block0(&ctx, idx, 1, &ct_block_0).expect("gpu");
        let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");

        assert_eq!(&pt_cpu[..16], &pts_gpu[..16], "kernel idx={idx}");
    }
}

// ============================================================================
// 4.6 Production state — read-only validation (skip si no hay)
// ============================================================================

#[test]
fn test_real_progress_toml_loadable_if_present() {
    let path = PathBuf::from("state/progress.toml");
    if !path.exists() {
        eprintln!("[skip] state/progress.toml no existe");
        return;
    }

    let progress: Progress = match load_progress_with_bak(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[skip/info] state/progress.toml no parsea con D-035 ({e}); \
                 probablemente es de pre-D-035 — borra con `quattro-crack reset --yes`."
            );
            return;
        }
    };
    assert!(
        progress.next_step <= N,
        "next_step fuera de rango: {}",
        progress.next_step
    );
    assert!(
        progress.tried >= progress.next_step,
        "tried < next_step: tried={}, next_step={}",
        progress.tried,
        progress.next_step
    );
    eprintln!(
        "production state: next_step={}, tried={}, elapsed_us={}, hits={}",
        progress.next_step,
        progress.tried,
        progress.elapsed_us,
        progress.hits.len()
    );
}

#[test]
fn test_kernel_runs_from_real_next_step_if_present() {
    let path = PathBuf::from("state/progress.toml");
    if !path.exists() {
        eprintln!("[skip] state/progress.toml no existe");
        return;
    }
    let progress: Progress = match load_progress_with_bak(&path) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("[skip] state/progress.toml no parsea, probablemente legacy.");
            return;
        }
    };
    let from_step = progress.next_step;
    if from_step >= N {
        eprintln!("[skip] barrido completado, from_step={}", from_step);
        return;
    }

    let count: u64 = 4096.min(N - from_step);

    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    let pts_gpu = gpu_dump_pt_block0(&ctx, from_step, count, &ct_block_0).expect("gpu");

    for j in (0..5u64).chain((count - 5)..count) {
        let idx = from_step + j;
        let pw = index_to_password(idx);
        let key = build_key_passraw(&pw);
        let pt_cpu = decrypt_aes128_ecb_raw(&key, &ct_block_0).expect("cpu");
        let off = (j as usize) * 16;
        assert_eq!(
            &pt_cpu[..16],
            &pts_gpu[off..off + 16],
            "kernel != cpu desde production next_step, j={j}, idx={idx}"
        );
    }

    eprintln!("D-035 kernel runs OK desde production next_step={from_step}, +{count} idx");
}
