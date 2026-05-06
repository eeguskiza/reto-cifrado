//! Tests bit-exact del kernel cooperativo intra-warp (D-030).
//!
//! Bloqueantes para aceptar Block 1:
//!
//! 1. `test_coop_dump_matches_reference_1m`: 1.000.000 idx contra
//!    `reference::decrypt_ecb_raw` (CPU). Cero discrepancias toleradas.
//! 2. `test_coop_dump_matches_legacy_dump_1m`: 1.000.000 idx contra el
//!    `dump_pt_block0` legacy (path AES-256 single-thread). Mismos bytes.
//! 3. `test_coop_brute_finds_synthetic_hit`: clave conocida `.lEonardo1452.`,
//!    el kernel cooperativo reporta el idx correcto.
//! 4. `test_coop_brute_matches_legacy_on_synthetic`: ambos kernels reportan
//!    el mismo idx para la misma síntesis.
//! 5. `test_coop_brute_no_false_positives_1m`: PT aleatorio sin Leonardo,
//!    cero hits reportados sobre 1M idx.

use quattro_crack::combinatorics::{index_to_password, password_to_index, N};
use quattro_crack::cuda::{
    gpu_dump_pt_block0, gpu_dump_pt_block0_coop, CudaCtx, KernelBundle, KernelBundleCoop,
};
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{decrypt_ecb_raw, encrypt_ecb_pkcs7, KNOWN_PREFIX_32};

/// PRNG determinista (LCG) para sampling reproducible.
fn rand_indices(seed: u64, count: usize) -> Vec<u64> {
    let mut state = seed;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(state % N);
    }
    out
}

/// CT block arbitrario con bytes variados (mismo que en optimized_kernel_parity).
fn fixed_ct_block() -> [u8; 16] {
    let mut b = [0u8; 16];
    for (i, slot) in b.iter_mut().enumerate() {
        *slot = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
    }
    b
}

#[test]
fn test_coop_dump_matches_reference_1m() {
    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    // Cobertura combinada: 5 chunks contiguos de 200K idx en posiciones
    // diversas del espacio (origen, mitad, casi-fin) + sampling random
    // adicional dentro de cada chunk para verificar consistencia interna.
    let chunk_size: u64 = 200_000;
    let chunk_starts: [u64; 5] = [
        0,
        100_000_000,
        N / 2,
        N - 2 * chunk_size,
        N - chunk_size,
    ];

    let mut total_verified: u64 = 0;
    for &base in chunk_starts.iter() {
        let pts_gpu = gpu_dump_pt_block0_coop(&ctx, base, chunk_size, &ct_block_0)
            .expect("gpu_dump_pt_block0_coop");
        assert_eq!(pts_gpu.len(), (chunk_size as usize) * 16);

        // Verifica los 200K bytes-a-bytes contra reference. CPU es lenta
        // pero el chunk es pequeño y sólo lo hacemos 5 veces.
        for j in 0..chunk_size {
            let idx = base + j;
            let pw = index_to_password(idx);
            let key = derive_md5hex(&pw);
            let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu decrypt");
            let off = (j as usize) * 16;
            let pt_gpu = &pts_gpu[off..off + 16];
            if &pt_cpu[..16] != pt_gpu {
                panic!(
                    "discrepancia coop↔reference en idx={idx}\n  cpu={:02x?}\n  gpu={:02x?}",
                    &pt_cpu[..16],
                    pt_gpu
                );
            }
        }
        total_verified += chunk_size;
    }
    eprintln!("coop bit-exact verificadas {total_verified} idx contra reference");
    assert!(total_verified >= 1_000_000);
}

#[test]
fn test_coop_dump_matches_legacy_dump_1m() {
    let ctx = CudaCtx::init().expect("CUDA");
    let ct_block_0 = fixed_ct_block();

    // Comparación coop↔legacy dump en chunks de 100K. La equivalencia
    // garantiza que, asumiendo legacy correcto (ya validado por su test
    // de paridad contra reference), coop también lo es.
    let chunk_size: u64 = 100_000;
    let chunk_starts = rand_indices(0x0000_c007_a55a_a000_u64, 10);

    let mut total_verified: u64 = 0;
    for &raw_start in chunk_starts.iter() {
        let base = raw_start.min(N - chunk_size);
        let pts_legacy = gpu_dump_pt_block0(&ctx, base, chunk_size, &ct_block_0)
            .expect("legacy dump");
        let pts_coop = gpu_dump_pt_block0_coop(&ctx, base, chunk_size, &ct_block_0)
            .expect("coop dump");

        if pts_legacy != pts_coop {
            // Encuentra primera diferencia.
            for j in 0..(chunk_size as usize) {
                let off = j * 16;
                if pts_legacy[off..off + 16] != pts_coop[off..off + 16] {
                    panic!(
                        "discrepancia coop↔legacy en idx={}\n  legacy={:02x?}\n  coop  ={:02x?}",
                        base + j as u64,
                        &pts_legacy[off..off + 16],
                        &pts_coop[off..off + 16]
                    );
                }
            }
            unreachable!("buffers difieren pero no encuentro idx — bug en el test");
        }
        total_verified += chunk_size;
    }
    eprintln!("coop bit-exact verificadas {total_verified} idx contra legacy dump");
    assert!(total_verified >= 1_000_000);
}

#[test]
fn test_coop_brute_finds_synthetic_hit() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válida");

    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let key = derive_md5hex(pw);
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let mut bundle = KernelBundleCoop::load(&ctx).expect("load coop");

    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch coop");
    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "kernel coop no encuentra target_idx={target_idx}; hits={hits:?}"
    );
}

#[test]
fn test_coop_brute_matches_legacy_on_synthetic() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw válida");

    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }

    let ctx = CudaCtx::init().expect("CUDA");
    let key = derive_md5hex(pw);
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let mut legacy = KernelBundle::load(&ctx).expect("load legacy");
    let mut coop = KernelBundleCoop::load(&ctx).expect("load coop");

    const RANGE: u64 = 200_000;
    let base = target_idx.saturating_sub(RANGE / 2);

    let hits_legacy = legacy.launch(base, RANGE, &ct_block_0).expect("launch legacy");
    let hits_coop = coop.launch(base, RANGE, &ct_block_0).expect("launch coop");

    let mut idxs_legacy: Vec<u64> = hits_legacy.iter().map(|h| h.idx).collect();
    let mut idxs_coop: Vec<u64> = hits_coop.iter().map(|h| h.idx).collect();
    idxs_legacy.sort();
    idxs_coop.sort();
    assert_eq!(
        idxs_legacy, idxs_coop,
        "legacy y coop reportan hits distintos sobre [{base}, {base}+{RANGE})"
    );
    assert!(idxs_coop.contains(&target_idx));
}

#[test]
fn test_coop_brute_no_false_positives_1m() {
    // CT que descifra a algo que NO empieza con Leonardo bajo NINGUNA
    // clave del espacio (estadísticamente cierto). Verifica que el
    // kernel coop no reporta hits espurios sobre 1M idx contiguos.
    let ct_block_0 = {
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(31).wrapping_add(0x12);
        }
        b
    };

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundleCoop::load(&ctx).expect("load coop");

    const RANGE: u64 = 1_000_000;
    let base = N / 3;
    let hits = bundle
        .launch(base, RANGE, &ct_block_0)
        .expect("launch coop");
    assert!(
        hits.is_empty(),
        "false positives coop sobre [{base}, {base}+{RANGE}): {hits:?}"
    );
}
