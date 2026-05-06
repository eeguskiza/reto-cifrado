// brute.cu — kernel principal del barrido AES-CBC.
//
// **Una única definición** parametrizada vía macros del compilador (D-011):
//
//   nvcc -DKDF_ID=<0..8> -DKEY_LEN=<16|32> ...
//
// build.rs invoca nvcc 9 veces, una por (kdf_id, key_len). El runtime carga
// el PTX correspondiente al KDF de la configuración activa.
//
// PERF (D-009): las T-tables AES (Td0..Td3 + INV_SBOX) se copian de
// __constant__ a __shared__ una vez por block al arrancar y cada thread
// las consulta desde __shared__. Esto evita la serialización del puerto
// de constant memory cuando los hilos acceden a direcciones distintas
// (caso típico en cualquier T-table lookup driven-by-data).
//
// Sin printf, sin malloc device, sin dispatch dinámico por modo, sin
// passwords por PCIe (los genera el kernel).

#include <stdint.h>
#include "gen.cuh"
#include "md5.cuh"
#include "aes.cuh"

#ifndef KDF_ID
#error "KDF_ID debe definirse al compilar brute.cu (rango 0..13)"
#endif
#ifndef KEY_LEN
#error "KEY_LEN debe definirse al compilar brute.cu (16, 24 o 32)"
#endif

// Hit emitido por el kernel — coincide bit a bit con el `DeviceHit` de Rust.
struct DeviceHit {
    uint64_t idx;
    uint32_t kdf_id;
    uint32_t iv_id;
};

// ---------- KDF dispatch (compile-time switch) ----------

__forceinline__ __device__ void derive_key(const uint8_t pw[14], uint8_t key[KEY_LEN]) {
    #if KDF_ID == 0
        md5_compute(pw, 14, key);
    #elif KDF_ID == 1
        uint8_t le[28];
        #pragma unroll
        for (int i = 0; i < 14; ++i) {
            le[i * 2 + 0] = pw[i];
            le[i * 2 + 1] = 0;
        }
        md5_compute(le, 28, key);
    #elif KDF_ID == 2
        uint8_t be[28];
        #pragma unroll
        for (int i = 0; i < 14; ++i) {
            be[i * 2 + 0] = 0;
            be[i * 2 + 1] = pw[i];
        }
        md5_compute(be, 28, key);
    #elif KDF_ID == 3
        uint8_t mid[16];
        md5_compute(pw, 14, mid);
        md5_compute_md5(mid, key);
    #elif KDF_ID == 4
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            key[i]      = h[i];
            key[i + 16] = h[i];
        }
    #elif KDF_ID == 5
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            key[i]      = h[i];
            key[i + 16] = h[15 - i];
        }
    #elif KDF_ID == 6
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            uint8_t hi = (uint8_t)((h[i] >> 4) & 0xfu);
            uint8_t lo = (uint8_t)(h[i] & 0xfu);
            key[i * 2 + 0] = (uint8_t)((hi < 10u) ? ('0' + hi) : ('a' + hi - 10u));
            key[i * 2 + 1] = (uint8_t)((lo < 10u) ? ('0' + lo) : ('a' + lo - 10u));
        }
    #elif KDF_ID == 7
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 8; ++i) {
            uint8_t hi = (uint8_t)((h[i] >> 4) & 0xfu);
            uint8_t lo = (uint8_t)(h[i] & 0xfu);
            key[i * 2 + 0] = (uint8_t)((hi < 10u) ? ('0' + hi) : ('a' + hi - 10u));
            key[i * 2 + 1] = (uint8_t)((lo < 10u) ? ('0' + lo) : ('a' + lo - 10u));
        }
    #elif KDF_ID == 8
        #pragma unroll
        for (int i = 0; i < 14; ++i) key[i] = pw[i];
        key[14] = 0;
        key[15] = 0;

    // ---------- Fase 3.5 — IDs 9..13 ----------
    #elif KDF_ID == 9
        // evp_md5_aes256_nosalt: D_1 = MD5(pw); D_2 = MD5(D_1 ‖ pw); key = D_1‖D_2
        uint8_t d1[16];
        md5_compute(pw, 14, d1);
        uint8_t d2_input[30];
        #pragma unroll
        for (int i = 0; i < 16; ++i) d2_input[i] = d1[i];
        #pragma unroll
        for (int i = 0; i < 14; ++i) d2_input[16 + i] = pw[i];
        uint8_t d2[16];
        md5_compute(d2_input, 30, d2);
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            key[i]      = d1[i];
            key[i + 16] = d2[i];
        }
    #elif KDF_ID == 10
        // evp_md5_aes192_nosalt: primeros 24 B de D_1‖D_2
        uint8_t d1[16];
        md5_compute(pw, 14, d1);
        uint8_t d2_input[30];
        #pragma unroll
        for (int i = 0; i < 16; ++i) d2_input[i] = d1[i];
        #pragma unroll
        for (int i = 0; i < 14; ++i) d2_input[16 + i] = pw[i];
        uint8_t d2[16];
        md5_compute(d2_input, 30, d2);
        #pragma unroll
        for (int i = 0; i < 16; ++i) key[i]      = d1[i];
        #pragma unroll
        for (int i = 0; i <  8; ++i) key[i + 16] = d2[i];
    #elif KDF_ID == 11
        // md5_trunc24: MD5(pw) ‖ MD5(pw)[:8]
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 16; ++i) key[i]      = h[i];
        #pragma unroll
        for (int i = 0; i <  8; ++i) key[i + 16] = h[i];
    #elif KDF_ID == 12
        // md5_md5x2_24: MD5(pw) ‖ MD5(MD5(pw))[:8]
        uint8_t h[16];
        md5_compute(pw, 14, h);
        uint8_t h2[16];
        md5_compute_md5(h, h2);
        #pragma unroll
        for (int i = 0; i < 16; ++i) key[i]      = h[i];
        #pragma unroll
        for (int i = 0; i <  8; ++i) key[i + 16] = h2[i];
    #elif KDF_ID == 13
        // md5hex_lo24: primeros 24 chars ASCII de hex(MD5(pw))
        uint8_t h[16];
        md5_compute(pw, 14, h);
        #pragma unroll
        for (int i = 0; i < 12; ++i) {
            uint8_t hi = (uint8_t)((h[i] >> 4) & 0xfu);
            uint8_t lo = (uint8_t)(h[i] & 0xfu);
            key[i * 2 + 0] = (uint8_t)((hi < 10u) ? ('0' + hi) : ('a' + hi - 10u));
            key[i * 2 + 1] = (uint8_t)((lo < 10u) ? ('0' + lo) : ('a' + lo - 10u));
        }
    #else
        #error "KDF_ID fuera de rango 0..13"
    #endif
}

// ---------- kernel ----------
//
// PERF (D-022): `__launch_bounds__(BLOCK_DIM, BLOCKS_PER_SM)` fuerza al
// compilador a producir código con como mucho `BLOCK_DIM × BLOCKS_PER_SM`
// threads/SM, lo que limita registros/thread. Sin esta directiva, ptxas
// elegía 128 regs/thread → ocupancy 25 % en sm_120 con 64K regs/SM.
// Con (128, 6) baja a 80 regs y ~37.5 % occupancy (48 B stack frame =
// spills mínimos a local memory). Medido tras Step 2 — ver D-022.
#ifndef QC_BLOCK_DIM
#define QC_BLOCK_DIM 128
#endif
#ifndef QC_BLOCKS_PER_SM
#define QC_BLOCKS_PER_SM 6
#endif

extern "C" __global__
__launch_bounds__(QC_BLOCK_DIM, QC_BLOCKS_PER_SM)
void brute_kernel(
    uint64_t idx_base,
    uint64_t idx_count,
    const uint8_t* __restrict__ iv_arg,        // 16 B; ignorado si iv_mode != 0
    uint32_t iv_mode,                            // 0=first16, 1=zeros, 2=md5pw
    const uint8_t* __restrict__ ct_block_0,    // 16 B
    DeviceHit* __restrict__ hits_out,
    uint32_t* __restrict__ hit_counter,
    uint32_t hits_capacity
) {
    // ---------- Bloque 0: copia cooperativa de tablas a __shared__ ----------
    // Td0..Td3 + INV_SBOX para el cuerpo del decrypt; SBOX para
    // aes_inv_mix_column_via_td0 dentro del key-schedule.
    __shared__ uint32_t s_td0[256];
    __shared__ uint32_t s_td1[256];
    __shared__ uint32_t s_td2[256];
    __shared__ uint32_t s_td3[256];
    __shared__ uint8_t  s_isbox[256];
    __shared__ uint8_t  s_sbox[256];
    __shared__ uint8_t  s_iv[16];
    __shared__ uint8_t  s_ct[16];

    {
        int tid_in_block = (int)threadIdx.x;
        int bs = (int)blockDim.x;
        for (int i = tid_in_block; i < 256; i += bs) {
            s_td0[i]   = QC_AES_TD0[i];
            s_td1[i]   = QC_AES_TD1[i];
            s_td2[i]   = QC_AES_TD2[i];
            s_td3[i]   = QC_AES_TD3[i];
            s_isbox[i] = QC_AES_INV_SBOX[i];
            s_sbox[i]  = QC_AES_SBOX[i];
        }
        if (tid_in_block < 16) {
            s_iv[tid_in_block] = iv_arg[tid_in_block];
            s_ct[tid_in_block] = ct_block_0[tid_in_block];
        }
    }
    __syncthreads();

    // ---------- Hot loop ----------
    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;
    uint64_t total_threads = (uint64_t)gridDim.x * (uint64_t)blockDim.x;

    for (uint64_t pos = tid; pos < idx_count; pos += total_threads) {
        uint64_t idx = idx_base + pos;

        // 1) password in-device
        uint8_t pw[14];
        index_to_password(idx, pw);

        // 2) KDF → key
        uint8_t key[KEY_LEN];
        derive_key(pw, key);

        // 3) resolver IV
        uint8_t iv_local[16];
        if (iv_mode == 0u) {
            #pragma unroll
            for (int i = 0; i < 16; ++i) iv_local[i] = s_iv[i];
        } else if (iv_mode == 1u) {
            #pragma unroll
            for (int i = 0; i < 16; ++i) iv_local[i] = 0;
        } else /* iv_mode == 2 */ {
            md5_compute(pw, 14, iv_local);
        }

        // 4) AES decrypt single block (tablas en __shared__)
        uint8_t pt_block[16];
        #if KEY_LEN == 16
            uint32_t rk[44];
            aes128_set_key_with_tables(key, rk, s_td0, s_sbox);
            aes128_decrypt_block_ptr(rk, s_ct, pt_block,
                s_td0, s_td1, s_td2, s_td3, s_isbox);
        #elif KEY_LEN == 24
            uint32_t rk[52];
            aes192_set_key_with_tables(key, rk, s_td0, s_sbox);
            aes192_decrypt_block_ptr(rk, s_ct, pt_block,
                s_td0, s_td1, s_td2, s_td3, s_isbox);
        #elif KEY_LEN == 32
            uint32_t rk[60];
            aes256_set_key_with_tables(key, rk, s_td0, s_sbox);
            aes256_decrypt_block_ptr(rk, s_ct, pt_block,
                s_td0, s_td1, s_td2, s_td3, s_isbox);
        #else
            #error "KEY_LEN debe ser 16, 24 o 32"
        #endif

        // 5) XOR-IV inline + comparación unrolled vs "Leonardo da Vinc"
        uint32_t pt0 = aes_get_u32_le(pt_block +  0) ^ aes_get_u32_le(iv_local +  0);
        uint32_t pt1 = aes_get_u32_le(pt_block +  4) ^ aes_get_u32_le(iv_local +  4);
        uint32_t pt2 = aes_get_u32_le(pt_block +  8) ^ aes_get_u32_le(iv_local +  8);
        uint32_t pt3 = aes_get_u32_le(pt_block + 12) ^ aes_get_u32_le(iv_local + 12);

        uint32_t a = pt0 ^ 0x6E6F654Cu;  // "Leon"
        uint32_t b = pt1 ^ 0x6F647261u;  // "ardo"
        uint32_t c = pt2 ^ 0x20616420u;  // " da "
        uint32_t d = pt3 ^ 0x636E6956u;  // "Vinc"

        if ((a | b | c | d) == 0u) {
            uint32_t slot = atomicAdd(hit_counter, 1u);
            if (slot < hits_capacity) {
                hits_out[slot].idx    = idx;
                hits_out[slot].kdf_id = (uint32_t)KDF_ID;
                hits_out[slot].iv_id  = iv_mode;
            }
        }
    }
}
