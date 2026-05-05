//! Bindings runtime CUDA con `cudarc 0.19`.
//!
//! Responsabilidades de este módulo:
//!
//! - Inicializar el contexto CUDA y seleccionar la GPU 0.
//! - Cargar los PTX precompilados por `build.rs` (1 por KDF, más
//!   `dump_passwords` para tests de paridad).
//! - Ofrecer `KernelBundle::launch` que ejecuta el barrido de un rango
//!   de índices y devuelve los hits encontrados.
//!
//! **Anti-pattern recordado**: la generación de candidatas vive en el
//! kernel; host solo pasa `idx_base` + `idx_count`. Cero passwords por
//! PCIe.

#![allow(dead_code)]

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use cudarc::driver::{
    CudaContext, CudaFunction, CudaModule, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::Ptx;

use crate::config::{IvSource, Kdf};

/// Tamaño del buffer de hits por batch. >256 entries con margen para que
/// el test "100 hits simultáneos" no sature jamás (D-006 / spec §3.4-§7).
pub const HITS_CAPACITY: u32 = 1024;

/// Hit emitido por el kernel — coincide bit a bit con el struct C++.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct DeviceHit {
    pub idx: u64,
    pub kdf_id: u32,
    pub iv_id: u32,
}

/// Contexto CUDA + stream por defecto. Inicialízalo una vez por proceso.
pub struct CudaCtx {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
}

impl CudaCtx {
    /// Inicializa CUDA, selecciona la GPU 0 y crea el stream por defecto.
    pub fn init() -> Result<Self> {
        let ctx = CudaContext::new(0).context("CudaContext::new(0): ¿hay una NVIDIA visible?")?;
        let stream = ctx.default_stream();
        Ok(Self { ctx, stream })
    }

    pub fn device_name(&self) -> Result<String> {
        Ok(self.ctx.name()?)
    }

    pub fn stream(&self) -> &Arc<CudaStream> {
        &self.stream
    }

    pub fn raw_ctx(&self) -> &Arc<CudaContext> {
        &self.ctx
    }
}

// ----- Kernel auxiliar de paridad -----

/// PTX precompilado por build.rs para el kernel auxiliar `dump_passwords`.
/// Embebido como string al binario; cudarc lo carga por puntero.
const PTX_DUMP_PASSWORDS: &str =
    include_str!(concat!(env!("OUT_DIR"), "/dump_passwords.ptx"));

/// Vuelca, para cada `idx ∈ [base, base+count)`, los 14 bytes del password
/// generado in-device. Útil **solo** para el test de paridad CPU↔GPU.
pub fn gpu_dump_passwords(ctx: &CudaCtx, idx_base: u64, idx_count: u64) -> Result<Vec<u8>> {
    let stream = ctx.stream().clone();
    let module: Arc<CudaModule> = ctx
        .raw_ctx()
        .load_module(Ptx::from_src(PTX_DUMP_PASSWORDS))?;
    let func: CudaFunction = module.load_function("dump_passwords")?;

    let total_bytes = (idx_count as usize) * 14;
    let mut out_dev: CudaSlice<u8> = stream.alloc_zeros::<u8>(total_bytes)?;

    let block_dim: u32 = 256;
    let grid_dim: u32 = idx_count.div_ceil(block_dim as u64) as u32;
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };

    let mut launch = stream.launch_builder(&func);
    launch.arg(&idx_base);
    launch.arg(&idx_count);
    launch.arg(&mut out_dev);
    unsafe { launch.launch(cfg) }?;

    stream.synchronize()?;
    let host = stream.clone_dtoh(&out_dev)?;
    Ok(host)
}

// ----- Helpers de test para las primitivas (MD5, AES) -----

/// PTX del kernel de test de MD5 device.
const PTX_MD5_TEST: &str = include_str!(concat!(env!("OUT_DIR"), "/md5_test.ptx"));

/// Calcula MD5 device para un batch de inputs y devuelve `n_inputs * 16` bytes.
///
/// `data` es el buffer empaquetado: cada slot ocupa `stride` bytes; los
/// primeros `lens[i]` bytes del slot `i` son el input válido.
pub fn gpu_md5_batch(
    ctx: &CudaCtx,
    data: &[u8],
    lens: &[u32],
    stride: u32,
) -> Result<Vec<u8>> {
    let n_inputs = lens.len() as u32;
    assert_eq!(data.len(), (n_inputs as usize) * (stride as usize));

    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_MD5_TEST))?;
    let func = module.load_function("md5_test")?;

    let data_dev = stream.clone_htod(data)?;
    let lens_dev = stream.clone_htod(lens)?;
    let mut out_dev: CudaSlice<u8> = stream.alloc_zeros::<u8>(n_inputs as usize * 16)?;

    let block_dim: u32 = 64;
    let grid_dim: u32 = n_inputs.div_ceil(block_dim);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };

    let mut launch = stream.launch_builder(&func);
    launch.arg(&data_dev);
    launch.arg(&lens_dev);
    launch.arg(&stride);
    launch.arg(&n_inputs);
    launch.arg(&mut out_dev);
    unsafe { launch.launch(cfg) }?;

    stream.synchronize()?;
    Ok(stream.clone_dtoh(&out_dev)?)
}

/// `MD5(MD5(in))` para un batch de digests de 16 B.
pub fn gpu_md5_md5_batch(ctx: &CudaCtx, digests: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(digests.len() % 16, 0);
    let n = (digests.len() / 16) as u32;

    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_MD5_TEST))?;
    let func = module.load_function("md5_md5_test")?;

    let dev_in = stream.clone_htod(digests)?;
    let mut dev_out: CudaSlice<u8> = stream.alloc_zeros::<u8>(digests.len())?;

    let block_dim: u32 = 64;
    let grid_dim: u32 = n.div_ceil(block_dim);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };

    let mut launch = stream.launch_builder(&func);
    launch.arg(&dev_in);
    launch.arg(&n);
    launch.arg(&mut dev_out);
    unsafe { launch.launch(cfg) }?;

    stream.synchronize()?;
    Ok(stream.clone_dtoh(&dev_out)?)
}

// ----- Helpers de test para AES device -----

/// PTX del kernel de test de AES device.
const PTX_AES_TEST: &str = include_str!(concat!(env!("OUT_DIR"), "/aes_test.ptx"));

/// AES-128 decrypt sobre un batch. `keys` = n*16 B, `cts` = n*16 B.
pub fn gpu_aes128_decrypt(ctx: &CudaCtx, keys: &[u8], cts: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(keys.len() % 16, 0);
    assert_eq!(cts.len() % 16, 0);
    let n = (keys.len() / 16) as u32;
    assert_eq!(n as usize * 16, cts.len());

    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_AES_TEST))?;
    let func = module.load_function("aes128_decrypt_test")?;

    let dev_keys = stream.clone_htod(keys)?;
    let dev_cts = stream.clone_htod(cts)?;
    let mut dev_pts: CudaSlice<u8> = stream.alloc_zeros::<u8>(n as usize * 16)?;

    let block_dim: u32 = 64;
    let grid_dim: u32 = n.div_ceil(block_dim);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };
    let mut launch = stream.launch_builder(&func);
    launch.arg(&dev_keys);
    launch.arg(&dev_cts);
    launch.arg(&n);
    launch.arg(&mut dev_pts);
    unsafe { launch.launch(cfg) }?;
    stream.synchronize()?;
    Ok(stream.clone_dtoh(&dev_pts)?)
}

/// AES-192 decrypt sobre un batch. `keys` = n*24 B, `cts` = n*16 B.
pub fn gpu_aes192_decrypt(ctx: &CudaCtx, keys: &[u8], cts: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(keys.len() % 24, 0);
    assert_eq!(cts.len() % 16, 0);
    let n = (keys.len() / 24) as u32;
    assert_eq!(n as usize * 16, cts.len());

    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_AES_TEST))?;
    let func = module.load_function("aes192_decrypt_test")?;

    let dev_keys = stream.clone_htod(keys)?;
    let dev_cts = stream.clone_htod(cts)?;
    let mut dev_pts: CudaSlice<u8> = stream.alloc_zeros::<u8>(n as usize * 16)?;

    let block_dim: u32 = 64;
    let grid_dim: u32 = n.div_ceil(block_dim);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };
    let mut launch = stream.launch_builder(&func);
    launch.arg(&dev_keys);
    launch.arg(&dev_cts);
    launch.arg(&n);
    launch.arg(&mut dev_pts);
    unsafe { launch.launch(cfg) }?;
    stream.synchronize()?;
    Ok(stream.clone_dtoh(&dev_pts)?)
}

/// AES-256 decrypt sobre un batch. `keys` = n*32 B, `cts` = n*16 B.
pub fn gpu_aes256_decrypt(ctx: &CudaCtx, keys: &[u8], cts: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(keys.len() % 32, 0);
    assert_eq!(cts.len() % 16, 0);
    let n = (keys.len() / 32) as u32;
    assert_eq!(n as usize * 16, cts.len());

    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_AES_TEST))?;
    let func = module.load_function("aes256_decrypt_test")?;

    let dev_keys = stream.clone_htod(keys)?;
    let dev_cts = stream.clone_htod(cts)?;
    let mut dev_pts: CudaSlice<u8> = stream.alloc_zeros::<u8>(n as usize * 16)?;

    let block_dim: u32 = 64;
    let grid_dim: u32 = n.div_ceil(block_dim);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };
    let mut launch = stream.launch_builder(&func);
    launch.arg(&dev_keys);
    launch.arg(&dev_cts);
    launch.arg(&n);
    launch.arg(&mut dev_pts);
    unsafe { launch.launch(cfg) }?;
    stream.synchronize()?;
    Ok(stream.clone_dtoh(&dev_pts)?)
}

// ----- Kernel de barrido principal -----

/// 14 PTX precompilados, uno por KDF (Fase 3 = 0..8, Fase 3.5 = 9..13).
/// Indexado por `Kdf::id()`.
const PTX_BRUTE: [&str; 14] = [
    include_str!(concat!(env!("OUT_DIR"), "/brute_0.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_1.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_2.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_3.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_4.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_5.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_6.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_7.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_8.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_9.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_10.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_11.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_12.ptx")),
    include_str!(concat!(env!("OUT_DIR"), "/brute_13.ptx")),
];

/// Tamaño de un `DeviceHit` empaquetado en el orden del struct C++.
/// `u64 + u32 + u32 = 16 B` con alineación natural.
const DEVICE_HIT_BYTES: usize = 16;

/// Bundle pre-cargado para un KDF concreto. Reutiliza buffers entre
/// llamadas consecutivas a `launch` para evitar allocaciones en el hot loop.
pub struct KernelBundle {
    kdf: Kdf,
    stream: Arc<CudaStream>,
    func: CudaFunction,
    iv_dev: CudaSlice<u8>,
    ct_block_dev: CudaSlice<u8>,
    hits_dev: CudaSlice<u8>,
    counter_dev: CudaSlice<u32>,
}

impl KernelBundle {
    pub fn load(ctx: &CudaCtx, kdf: Kdf) -> Result<Self> {
        let stream = ctx.stream().clone();
        let id = kdf.id() as usize;
        if id >= PTX_BRUTE.len() {
            return Err(anyhow!("kdf id {id} fuera de rango"));
        }
        let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_BRUTE[id]))?;
        let func = module.load_function("brute_kernel")?;

        let iv_dev = stream.alloc_zeros::<u8>(16)?;
        let ct_block_dev = stream.alloc_zeros::<u8>(16)?;
        let hits_dev = stream.alloc_zeros::<u8>(HITS_CAPACITY as usize * DEVICE_HIT_BYTES)?;
        let counter_dev = stream.alloc_zeros::<u32>(1)?;

        Ok(Self {
            kdf,
            stream,
            func,
            iv_dev,
            ct_block_dev,
            hits_dev,
            counter_dev,
        })
    }

    pub fn kdf(&self) -> Kdf {
        self.kdf
    }

    /// Lanza un batch de tamaño `idx_count` empezando en `idx_base`.
    /// `iv_bytes` se usa solo si `iv.iv_mode() == 0` (first16); para zeros
    /// se ignora y para md5pw lo calcula el kernel.
    pub fn launch(
        &mut self,
        idx_base: u64,
        idx_count: u64,
        iv_bytes: &[u8; 16],
        iv: IvSource,
        ct_block_0: &[u8; 16],
    ) -> Result<Vec<DeviceHit>> {
        let stream = self.stream.clone();

        // Reset counter y empuja IV + CT a device.
        stream.memset_zeros(&mut self.counter_dev)?;
        stream.memcpy_htod(iv_bytes.as_slice(), &mut self.iv_dev)?;
        stream.memcpy_htod(ct_block_0.as_slice(), &mut self.ct_block_dev)?;

        // Dimensiona grid. PERF: 128 threads/block balancea register pressure
        // (~96 regs/thread tras unroll AES) con occupancy. sm_120 acepta
        // grid_dim.x hasta 2^31-1; aun así capamos a 524 288 blocks (= 64M
        // threads) para no agotar contadores y porque el stride loop cubre
        // batches mayores con menos overhead de lanzamiento.
        let block_dim: u32 = 128;
        let needed_blocks = idx_count.div_ceil(block_dim as u64);
        let grid_dim: u32 = needed_blocks.min(524_288) as u32;

        let cfg = LaunchConfig {
            grid_dim: (grid_dim, 1, 1),
            block_dim: (block_dim, 1, 1),
            shared_mem_bytes: 0,
        };

        let iv_mode: u32 = iv.iv_mode();
        let capacity: u32 = HITS_CAPACITY;

        let mut launch = stream.launch_builder(&self.func);
        launch.arg(&idx_base);
        launch.arg(&idx_count);
        launch.arg(&self.iv_dev);
        launch.arg(&iv_mode);
        launch.arg(&self.ct_block_dev);
        launch.arg(&mut self.hits_dev);
        launch.arg(&mut self.counter_dev);
        launch.arg(&capacity);
        unsafe { launch.launch(cfg) }?;

        stream.synchronize()?;

        let counter_host = stream.clone_dtoh(&self.counter_dev)?;
        let count = counter_host[0];
        if count > HITS_CAPACITY {
            return Err(anyhow!(
                "hit_counter={count} > HITS_CAPACITY={HITS_CAPACITY}: \
                 buffer subdimensionado o bug en el kernel. Aborta y revisa."
            ));
        }

        let hits_bytes = stream.clone_dtoh(&self.hits_dev)?;
        let mut hits = Vec::with_capacity(count as usize);
        for i in 0..(count as usize) {
            let off = i * DEVICE_HIT_BYTES;
            let idx = u64::from_le_bytes(hits_bytes[off..off + 8].try_into().unwrap());
            let kdf_id = u32::from_le_bytes(hits_bytes[off + 8..off + 12].try_into().unwrap());
            let iv_id = u32::from_le_bytes(hits_bytes[off + 12..off + 16].try_into().unwrap());
            hits.push(DeviceHit { idx, kdf_id, iv_id });
        }
        Ok(hits)
    }
}

/// PTX del kernel auxiliar `force_emit_hits` para tests de capacidad.
const PTX_FORCE_EMIT_HITS: &str =
    include_str!(concat!(env!("OUT_DIR"), "/force_emit_hits.ptx"));

/// Lanza el kernel `force_emit_hits` que emite `n_target` hits sintéticos.
/// Devuelve `(reported_count, hits)`. Si `reported_count > capacity`, el
/// caller decide qué hacer (típicamente: rechazar el batch).
///
/// Útil **solo para tests** — no forma parte del barrido de producción.
pub fn gpu_force_emit_hits(
    ctx: &CudaCtx,
    n_target: u32,
) -> Result<(u32, Vec<DeviceHit>)> {
    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_FORCE_EMIT_HITS))?;
    let func = module.load_function("force_emit_hits")?;

    let mut hits_dev: CudaSlice<u8> =
        stream.alloc_zeros::<u8>(HITS_CAPACITY as usize * DEVICE_HIT_BYTES)?;
    let mut counter_dev: CudaSlice<u32> = stream.alloc_zeros::<u32>(1)?;
    stream.memset_zeros(&mut counter_dev)?;

    let block_dim: u32 = 256;
    let grid_dim: u32 = n_target.div_ceil(block_dim).max(1);
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };

    let capacity: u32 = HITS_CAPACITY;
    let mut launch = stream.launch_builder(&func);
    launch.arg(&n_target);
    launch.arg(&mut hits_dev);
    launch.arg(&mut counter_dev);
    launch.arg(&capacity);
    unsafe { launch.launch(cfg) }?;

    stream.synchronize()?;

    let counter_host = stream.clone_dtoh(&counter_dev)?;
    let count = counter_host[0];
    let hits_bytes = stream.clone_dtoh(&hits_dev)?;

    let n_to_read = count.min(HITS_CAPACITY) as usize;
    let mut hits = Vec::with_capacity(n_to_read);
    for i in 0..n_to_read {
        let off = i * DEVICE_HIT_BYTES;
        let idx = u64::from_le_bytes(hits_bytes[off..off + 8].try_into().unwrap());
        let kdf_id = u32::from_le_bytes(hits_bytes[off + 8..off + 12].try_into().unwrap());
        let iv_id = u32::from_le_bytes(hits_bytes[off + 12..off + 16].try_into().unwrap());
        hits.push(DeviceHit { idx, kdf_id, iv_id });
    }
    Ok((count, hits))
}

/// Resuelve el IV efectivo para un launch dado (bytes que se mandan al device).
pub fn resolve_iv_bytes(iv: IvSource, file_iv: &[u8; 16]) -> [u8; 16] {
    match iv {
        IvSource::First16 => *file_iv,
        IvSource::Zeros => [0u8; 16],
        IvSource::Md5Pw => [0u8; 16], // ignorado por el kernel, lo calcula in-device
    }
}
