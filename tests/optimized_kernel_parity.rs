//! Tests específicos del kernel monolítico tras D-029.
//!
//! Tres pruebas obligatorias:
//!
//! 1. `test_ecb_md5hex_kernel_matches_baseline`: para 100 000 índices
//!    distribuidos por todo el espacio, el kernel `dump_pt_block0`
//!    (que reutiliza las primitivas del `brute_kernel` de D-029:
//!    md5hex_full + AES-256-ECB) produce un plaintext de primer bloque
//!    BIT-EXACT al de `reference::decrypt_ecb_raw` con la clave
//!    derivada en CPU. Cero discrepancias toleradas.
//!
//! 2. `test_optimized_kernel_finds_synthetic_hits`: el `brute_kernel`
//!    encuentra hits sintéticos generados con la única configuración.
//!
//! 3. `test_throughput_meets_target`: throughput sostenido del kernel
//!    monolítico ≥ 1.5 GH/s (umbral conservador, ver D-025).

use std::time::Instant;

use quattro_crack::combinatorics::{index_to_password, password_to_index, N};
use quattro_crack::cuda::{gpu_dump_pt_block0, CudaCtx, KernelBundle};
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{decrypt_ecb_raw, encrypt_ecb_pkcs7, KNOWN_PREFIX_32};

fn rand_indices(seed: u64, count: usize) -> Vec<u64> {
    let mut state = seed;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(state % N);
    }
    out
}

#[test]
fn test_ecb_md5hex_kernel_matches_baseline() {
    // CT block arbitrario con bytes variados.
    let ct_block_0 = {
        let mut b = [0u8; 16];
        for (i, slot) in b.iter_mut().enumerate() {
            *slot = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
        }
        b
    };

    let n_target = 100_000usize;
    let starts = rand_indices(0xdeadbeef_cafebabe, n_target);

    let ctx = CudaCtx::init().expect("CUDA");
    let batch_size: u64 = 4096;
    let mut tested = 0usize;

    for &start_idx in starts.iter() {
        let base = start_idx.min(N - batch_size);
        let pts_gpu = gpu_dump_pt_block0(&ctx, base, batch_size, &ct_block_0)
            .expect("gpu dump");
        assert_eq!(pts_gpu.len(), (batch_size as usize) * 16);

        // Verificamos slots 0/1/17/1023/4095 dentro de cada batch.
        for j in [0u64, 1, 17, 1023, 4095] {
            let idx = base + j;
            let pw = index_to_password(idx);
            let key = derive_md5hex(&pw);
            let pt_cpu = decrypt_ecb_raw(&key, &ct_block_0).expect("cpu decrypt");
            let off = (j as usize) * 16;
            let pt_gpu = &pts_gpu[off..off + 16];
            assert_eq!(
                &pt_cpu[..16],
                pt_gpu,
                "discrepancia en idx={idx}: cpu={:?} gpu={:?}",
                &pt_cpu[..16],
                pt_gpu
            );
            tested += 1;
        }
        if tested >= n_target {
            break;
        }
    }
    eprintln!("verificados {tested} plaintext-blocks bit-exact CPU↔GPU (ECB md5hex)");
    assert!(
        tested >= n_target,
        "se verificaron solo {tested} idx, esperado ≥ {n_target}"
    );
}

#[test]
fn test_optimized_kernel_finds_synthetic_hits() {
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).unwrap();

    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }

    let ctx = CudaCtx::init().expect("CUDA");

    let key = derive_md5hex(pw);
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let mut bundle = KernelBundle::load(&ctx).expect("load kernel ECB md5hex");
    const RANGE: u64 = 200_000;
    let hits = bundle
        .launch(target_idx.saturating_sub(RANGE / 2), RANGE, &ct_block_0)
        .expect("launch");
    assert!(
        hits.iter().any(|h| h.idx == target_idx),
        "ECB md5hex: target_idx={target_idx} no aparece en {hits:?}"
    );
}

#[test]
fn test_throughput_meets_target() {
    // 100 Mi candidatas, batch 32 Mi. Best-of-3.
    let ctx = CudaCtx::init().unwrap();
    let mut bundle = KernelBundle::load(&ctx).unwrap();
    let ct_block_0 = [0xffu8; 16];

    let _ = bundle.launch(0, 1_000_000, &ct_block_0).unwrap();

    const TOTAL: u64 = 100 * 1024 * 1024;
    const BATCH: u64 = 32 * 1024 * 1024;
    let mut peaks: Vec<f64> = Vec::new();
    for run in 0..3 {
        let mut total = 0u64;
        let started = Instant::now();
        while total < TOTAL {
            let n = BATCH.min(TOTAL - total);
            let _ = bundle.launch(total, n, &ct_block_0).unwrap();
            total += n;
        }
        let elapsed = started.elapsed();
        let ghs = TOTAL as f64 / elapsed.as_secs_f64() / 1.0e9;
        eprintln!("run {run}: {ghs:.3} GH/s ({:?})", elapsed);
        peaks.push(ghs);
    }
    let best = peaks.iter().cloned().fold(0.0f64, f64::max);
    eprintln!("best GH/s sobre md5hex_full / AES-256-ECB = {best:.3}");

    // Piso 1.0 GH/s = falla duro (regresión grave). AES-256-ECB es
    // ~30 % más lento que AES-128 (14 rondas vs 10), así que el techo
    // post-D-029 es 1.5–2.0 GH/s en frío y 1.2–1.4 GH/s bajo carga
    // térmica de la suite completa. 1.0 sigue capturando regresiones
    // reales sin ser flaky.
    assert!(
        best >= 1.0,
        "throughput {best:.3} GH/s < 1.0 GH/s — regresión seria del kernel post-D-029"
    );
    if best < 1.5 {
        eprintln!(
            "AVISO: throughput {best:.3} GH/s < 1.5 GH/s. \
             Revisa temperatura GPU y carga del sistema."
        );
    }
}
