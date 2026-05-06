//! End-to-end sintéticos post-D-029: ciframos un plaintext con la
//! única configuración (`md5hex_full / aes-256-ecb / pkcs7`) y
//! verificamos que el kernel CUDA encuentra la clave en su rango.

use std::time::Instant;

use quattro_crack::combinatorics::{password_to_index, N};
use quattro_crack::cuda::{gpu_force_emit_hits, CudaCtx, KernelBundle};
use quattro_crack::kdf::derive_md5hex;
use quattro_crack::reference::{encrypt_ecb_pkcs7, validate_hit, HitVerdict, KNOWN_PREFIX_32};

/// Construye un plaintext de 1600 B que empieza con KNOWN_PREFIX_32 y
/// rellena con 'X' hasta cubrir 100 bloques. `encrypt_ecb_pkcs7` añade
/// 16 B de padding produciendo un CT de 1616 B = 101 bloques (matches
/// `Ciphertext::TOTAL_BIN_LEN`).
fn build_plaintext_1600() -> Vec<u8> {
    let mut pt = Vec::with_capacity(1600);
    pt.extend_from_slice(KNOWN_PREFIX_32);
    while pt.len() < 1600 {
        pt.push(b'X');
    }
    pt
}

#[test]
fn test_e2e_synthetic_ecb_md5hex_finds_synthetic_hit() {
    // Password real del espacio.
    let pw = b".lEonardo1452.";
    let target_idx = password_to_index(pw).expect("pw valido del espacio");
    eprintln!("target idx = {target_idx} (de N = {N})");

    let key = derive_md5hex(pw);
    let pt = build_plaintext_1600();
    let ct = encrypt_ecb_pkcs7(&key, &pt);
    assert_eq!(ct.len(), 1616);
    let ct_block_0: [u8; 16] = ct[..16].try_into().unwrap();

    let ctx = CudaCtx::init().expect("CUDA");
    let mut bundle = KernelBundle::load(&ctx).expect("load kernel ECB md5hex");

    const RANGE: u64 = 200_000;
    let idx_base = target_idx.saturating_sub(RANGE / 2);
    let idx_count = RANGE;

    let started = Instant::now();
    let hits = bundle
        .launch(idx_base, idx_count, &ct_block_0)
        .expect("launch");
    let elapsed = started.elapsed();
    eprintln!(
        "ECB md5hex launched {idx_count} idx in {:?} → {:.2} M idx/s, hits={}",
        elapsed,
        idx_count as f64 / elapsed.as_secs_f64() / 1.0e6,
        hits.len()
    );

    assert!(!hits.is_empty(), "el kernel no encontró el hit");
    let found = hits.iter().any(|h| h.idx == target_idx);
    assert!(found, "target_idx={target_idx} no aparece en {hits:?}");

    // Triple validación CPU sobre el primer hit.
    for h in &hits {
        if h.idx != target_idx {
            continue;
        }
        let verdict = validate_hit(&key, &ct).unwrap();
        assert!(
            matches!(verdict, HitVerdict::Confirmed { .. }),
            "validate_hit no devolvió Confirmed: {verdict:?}"
        );
    }
}

#[test]
fn test_hit_buffer_handles_100_simultaneous_hits() {
    // El path brute es estructuralmente incapaz de generar 100 hits en
    // un único launch. Validamos por tanto la INFRAESTRUCTURA de hits
    // con un kernel sintético que fuerza N emisiones.
    let ctx = CudaCtx::init().expect("CUDA");

    let (count, hits) = gpu_force_emit_hits(&ctx, 100).expect("force 100");
    assert_eq!(count, 100, "el contador atómico debe sumar exactamente 100");
    assert_eq!(hits.len(), 100);

    let (count, hits) = gpu_force_emit_hits(&ctx, 1024).expect("force 1024");
    assert_eq!(count, 1024);
    assert_eq!(hits.len(), 1024);

    let (count, hits) = gpu_force_emit_hits(&ctx, 2048).expect("force 2048");
    assert_eq!(count, 2048, "contador atómico cuenta TODOS los hits, capped o no");
    assert_eq!(hits.len(), 1024, "solo se leen los primeros 'capacity' slots");
}

/// Throughput sostenido aproximado del kernel ECB md5hex.
#[test]
fn test_throughput_sustained() {
    let ctx = CudaCtx::init().unwrap();
    let mut bundle = KernelBundle::load(&ctx).unwrap();

    let ct_block_0 = [0u8; 16];

    // Warmup
    let _ = bundle.launch(0, 1_000_000, &ct_block_0).unwrap();

    const BATCH: u64 = 128 * 1024 * 1024;
    let mut best_ghs = 0.0f64;
    for run in 0..5 {
        let started = Instant::now();
        let _ = bundle.launch(0, BATCH, &ct_block_0).unwrap();
        let elapsed = started.elapsed();
        let ghs = BATCH as f64 / elapsed.as_secs_f64() / 1.0e9;
        eprintln!("run {run}: {ghs:.3} GH/s ({:?})", elapsed);
        if ghs > best_ghs {
            best_ghs = ghs;
        }
    }
    eprintln!(
        "throughput md5hex_full / AES-256-ECB sostenido (best of 5) ≈ {best_ghs:.3} GH/s"
    );
    assert!(
        best_ghs >= 1.0,
        "throughput {best_ghs:.3} GH/s por debajo del piso 1 GH/s; \
         algo va muy mal con el kernel"
    );
}
