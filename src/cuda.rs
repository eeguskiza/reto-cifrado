//! Bindings runtime CUDA con `cudarc 0.19`.
//!
//! Tras D-029, el barrido tiene un único kernel
//! (`brute_md5hex_aes256_ecb.cu`). Eliminamos el array `PTX_BRUTE` por
//! KDF y simplificamos `KernelBundle::load()` para no recibir parámetros.
//! `launch` ya no recibe IV (ECB no lo usa).
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

/// Tamaño del buffer de hits por batch. >256 entries con margen para
/// que el test "100 hits simultáneos" no sature jamás.
pub const HITS_CAPACITY: u32 = 1024;

/// Hit emitido por el kernel — coincide bit a bit con el struct C++.
/// Tras D-029 solo lleva `idx`: kdf/iv son implícitos (única config).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct DeviceHit {
    pub idx: u64,
}

/// Contexto CUDA + stream por defecto. Inicialízalo una vez por proceso.
pub struct CudaCtx {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
}

impl CudaCtx {
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

// ----- Kernel auxiliar de paridad del generador -----

const PTX_DUMP_PASSWORDS: &str = include_str!(concat!(env!("OUT_DIR"), "/dump_passwords.ptx"));

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
    Ok(stream.clone_dtoh(&out_dev)?)
}

// ----- Helpers de test para MD5 / AES (FIPS-197 + RFC 1321) -----

const PTX_MD5_TEST: &str = include_str!(concat!(env!("OUT_DIR"), "/md5_test.ptx"));

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

const PTX_AES_TEST: &str = include_str!(concat!(env!("OUT_DIR"), "/aes_test.ptx"));

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

// ----- Kernel ÚNICO de barrido (D-029) -----

/// PTX único, embebido en el binario.
const PTX_BRUTE: &str = include_str!(concat!(env!("OUT_DIR"), "/brute_md5hex_aes256_ecb.ptx"));

/// Tamaño de un `DeviceHit` empaquetado: solo `u64 idx` = 8 B.
const DEVICE_HIT_BYTES: usize = 8;

/// Block dim compilada en `__launch_bounds__`. Debe coincidir.
pub const QC_BLOCK_DIM: u32 = 128;

/// N candidatas por thread en la stride-loop interna (D-024).
const QC_N_PER_THREAD: u64 = 8;

/// Cap absoluto de bloques por launch (D-024).
const QC_MAX_GRID_BLOCKS: u32 = 4_096;

/// Bundle pre-cargado del único kernel activo. Reutiliza buffers entre
/// llamadas a `launch` para evitar allocaciones en el hot loop.
pub struct KernelBundle {
    stream: Arc<CudaStream>,
    func: CudaFunction,
    block_dim: u32,
    ct_block_dev: CudaSlice<u8>,
    hits_dev: CudaSlice<u8>,
    counter_dev: CudaSlice<u32>,
}

impl KernelBundle {
    /// Carga el único kernel activo (D-029). Sin parámetros.
    pub fn load(ctx: &CudaCtx) -> Result<Self> {
        let stream = ctx.stream().clone();
        let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_BRUTE))?;
        let func = module.load_function("brute_kernel")?;

        let ct_block_dev = stream.alloc_zeros::<u8>(16)?;
        let hits_dev = stream.alloc_zeros::<u8>(HITS_CAPACITY as usize * DEVICE_HIT_BYTES)?;
        let counter_dev = stream.alloc_zeros::<u32>(1)?;

        Ok(Self {
            stream,
            func,
            block_dim: QC_BLOCK_DIM,
            ct_block_dev,
            hits_dev,
            counter_dev,
        })
    }

    /// Lanza un batch de tamaño `idx_count` empezando en `idx_base`.
    /// `ct_block_0` son los primeros 16 B del fichero objetivo (en ECB,
    /// el primer bloque de ciphertext).
    pub fn launch(
        &mut self,
        idx_base: u64,
        idx_count: u64,
        ct_block_0: &[u8; 16],
    ) -> Result<Vec<DeviceHit>> {
        let stream = self.stream.clone();

        stream.memset_zeros(&mut self.counter_dev)?;
        stream.memcpy_htod(ct_block_0.as_slice(), &mut self.ct_block_dev)?;

        let block_dim: u32 = self.block_dim;
        let n_per_thread = QC_N_PER_THREAD;
        let needed_blocks = idx_count.div_ceil((block_dim as u64) * n_per_thread);
        let grid_dim: u32 = needed_blocks.clamp(1, QC_MAX_GRID_BLOCKS as u64) as u32;

        let cfg = LaunchConfig {
            grid_dim: (grid_dim, 1, 1),
            block_dim: (block_dim, 1, 1),
            shared_mem_bytes: 0,
        };

        let capacity: u32 = HITS_CAPACITY;

        let mut launch = stream.launch_builder(&self.func);
        launch.arg(&idx_base);
        launch.arg(&idx_count);
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
            hits.push(DeviceHit { idx });
        }
        Ok(hits)
    }
}

/// PTX del kernel auxiliar `force_emit_hits` para tests de capacidad.
const PTX_FORCE_EMIT_HITS: &str =
    include_str!(concat!(env!("OUT_DIR"), "/force_emit_hits.ptx"));

/// PTX del kernel auxiliar `dump_pt_block0` para tests bit-exact.
const PTX_DUMP_PT_BLOCK0: &str =
    include_str!(concat!(env!("OUT_DIR"), "/dump_pt_block0.ptx"));

/// Vuelca el plaintext del primer bloque (16 B) bajo md5hex_full +
/// AES-256-ECB para cada idx en `[idx_base, idx_base+idx_count)`.
/// Usado por `test_optimized_kernel_matches_baseline`.
pub fn gpu_dump_pt_block0(
    ctx: &CudaCtx,
    idx_base: u64,
    idx_count: u64,
    ct_block_0: &[u8; 16],
) -> Result<Vec<u8>> {
    let stream = ctx.stream().clone();
    let module = ctx
        .raw_ctx()
        .load_module(Ptx::from_src(PTX_DUMP_PT_BLOCK0))?;
    let func = module.load_function("dump_pt_block0")?;

    let ct_dev = stream.clone_htod(ct_block_0.as_slice())?;
    let total_bytes = (idx_count as usize) * 16;
    let mut pt_dev: CudaSlice<u8> = stream.alloc_zeros::<u8>(total_bytes)?;

    let block_dim: u32 = 128;
    let grid_dim: u32 = idx_count.div_ceil(block_dim as u64) as u32;
    let cfg = LaunchConfig {
        grid_dim: (grid_dim, 1, 1),
        block_dim: (block_dim, 1, 1),
        shared_mem_bytes: 0,
    };

    let mut launch = stream.launch_builder(&func);
    launch.arg(&idx_base);
    launch.arg(&idx_count);
    launch.arg(&ct_dev);
    launch.arg(&mut pt_dev);
    unsafe { launch.launch(cfg) }?;

    stream.synchronize()?;
    Ok(stream.clone_dtoh(&pt_dev)?)
}

/// Lanza el kernel `force_emit_hits` que emite `n_target` hits
/// sintéticos. Tras D-029, `DeviceHit` ya solo tiene `idx`, así que el
/// kernel sintético sigue siendo compatible (escribe `idx = tid`).
///
/// Devuelve `(reported_count, hits)`. Si `reported_count > capacity`,
/// el caller decide qué hacer.
pub fn gpu_force_emit_hits(
    ctx: &CudaCtx,
    n_target: u32,
) -> Result<(u32, Vec<DeviceHit>)> {
    let stream = ctx.stream().clone();
    let module = ctx.raw_ctx().load_module(Ptx::from_src(PTX_FORCE_EMIT_HITS))?;
    let func = module.load_function("force_emit_hits")?;

    let mut hits_dev: CudaSlice<u8> =
        stream.alloc_zeros::<u8>(HITS_CAPACITY as usize * 16)?; // legacy 16 B
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
    // El kernel legacy `force_emit_hits.cu` emite struct legacy de
    // 16 B (idx, kdf_id, iv_id). Tras D-029 solo nos interesa el `idx`.
    for i in 0..n_to_read {
        let off = i * 16;
        let idx = u64::from_le_bytes(hits_bytes[off..off + 8].try_into().unwrap());
        hits.push(DeviceHit { idx });
    }
    Ok((count, hits))
}
