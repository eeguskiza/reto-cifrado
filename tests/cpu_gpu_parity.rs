//! `test_cpu_gpu_generator_parity_first_million` — TEST BLOQUEANTE.
//!
//! Por cada idx ∈ [0, 1_000_000) genera el password en GPU (kernel
//! `dump_passwords`) y en CPU (`combinatorics::index_to_password`),
//! y compara byte a byte. Cero tolerancia: una sola discrepancia entre
//! los 14 millones de bytes hace fallar el test.
//!
//! Si pasa este test, el barrido GPU está garantizado a tocar exactamente
//! los mismos passwords que la CPU enumera. Si falla, todo el resto del
//! proyecto está construido sobre arena. **NO avances sin esto verde**.

use quattro_crack::combinatorics::index_to_password;
use quattro_crack::cuda::{gpu_dump_passwords, CudaCtx};

#[test]
fn test_cpu_gpu_generator_parity_first_million() {
    let ctx = match CudaCtx::init() {
        Ok(c) => c,
        Err(e) => panic!(
            "no se pudo inicializar CUDA: {e:?}. Comprueba `nvidia-smi` y \
             que tienes la GPU NVIDIA visible desde WSL2."
        ),
    };

    let device_name = ctx.device_name().unwrap_or_else(|_| "<unknown>".into());
    eprintln!("paridad CPU↔GPU sobre device: {device_name}");

    const N: u64 = 1_000_000;
    let host_bytes = gpu_dump_passwords(&ctx, 0, N).expect("gpu dump");
    assert_eq!(host_bytes.len(), (N as usize) * 14);

    let mut first_mismatch: Option<(u64, [u8; 14], [u8; 14])> = None;
    let mut mismatch_count: u64 = 0;
    for idx in 0..N {
        let cpu = index_to_password(idx);
        let gpu_slice = &host_bytes[(idx as usize) * 14..(idx as usize + 1) * 14];
        if gpu_slice != &cpu[..] {
            if first_mismatch.is_none() {
                let mut g = [0u8; 14];
                g.copy_from_slice(gpu_slice);
                first_mismatch = Some((idx, cpu, g));
            }
            mismatch_count += 1;
        }
    }

    if let Some((idx, cpu, gpu)) = first_mismatch {
        panic!(
            "paridad CPU↔GPU rota: {mismatch_count} discrepancias en [0, {N}).\n  \
             primera en idx={idx}\n  \
             cpu = {:?}\n  \
             gpu = {:?}",
            std::str::from_utf8(&cpu).unwrap_or("<no utf8>"),
            std::str::from_utf8(&gpu).unwrap_or("<no utf8>"),
        );
    }
    assert_eq!(mismatch_count, 0);
}

/// Sanity check pequeño: muestra los primeros 5 passwords generados en GPU
/// y en CPU. Útil para depurar si el test de 1M falla.
#[test]
fn test_cpu_gpu_first_five_match() {
    let ctx = CudaCtx::init().expect("init CUDA");
    let host_bytes = gpu_dump_passwords(&ctx, 0, 5).expect("dump 5");
    for idx in 0..5u64 {
        let cpu = index_to_password(idx);
        let gpu = &host_bytes[(idx as usize) * 14..(idx as usize + 1) * 14];
        assert_eq!(gpu, &cpu[..], "diff en idx={idx}");
    }
}

/// Cubre también un rango contiguo en mitad del espacio (no solo el origen).
#[test]
fn test_cpu_gpu_parity_offset_range() {
    let ctx = CudaCtx::init().expect("init CUDA");
    const BASE: u64 = 30_000_000_000_000;
    const COUNT: u64 = 100_000;
    let host_bytes = gpu_dump_passwords(&ctx, BASE, COUNT).expect("dump offset");
    for i in 0..COUNT {
        let idx = BASE + i;
        let cpu = index_to_password(idx);
        let gpu = &host_bytes[(i as usize) * 14..(i as usize + 1) * 14];
        assert_eq!(gpu, &cpu[..], "diff en idx={idx}");
    }
}
