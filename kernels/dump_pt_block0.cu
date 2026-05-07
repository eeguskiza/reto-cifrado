// dump_pt_block0.cu — kernel de diagnóstico SOLO para tests (D-035).
//
// Tras D-035: produce el plaintext de los primeros 16 B del CT objetivo
// bajo la única configuración activa real:
//
//   key  = password.encode() + b'\x00' * (16 - len(password.encode()))
//          (passraw, sin MD5 ni hexify)
//   mode = AES-128-ECB        (sin IV)
//
// Reutiliza las mismas primitivas (`aes128_set_key_with_tables`,
// `aes128_decrypt_block_ptr`) que el `brute_kernel` activo de D-035, así
// que si este kernel produce los plaintexts correctos byte-a-byte, el de
// barrido también.
//
// Validación bit-exact frente a `reference::decrypt_aes128_ecb_raw` de
// CPU vive en `tests/optimized_kernel_parity.rs` y
// `tests/d035_cifraronline_construction.rs`.

#include <stdint.h>
#include "gen.cuh"
#include "aes.cuh"

extern "C" __global__ void dump_pt_block0(
    uint64_t idx_base,
    uint64_t idx_count,
    const uint8_t* __restrict__ ct_block_0,
    uint8_t* __restrict__ pt_out                 // idx_count * 16 B
) {
    __shared__ uint32_t s_td0[256];
    __shared__ uint32_t s_td1[256];
    __shared__ uint32_t s_td2[256];
    __shared__ uint32_t s_td3[256];
    __shared__ uint8_t  s_isbox[256];
    __shared__ uint8_t  s_sbox[256];
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
            s_ct[tid_in_block] = ct_block_0[tid_in_block];
        }
    }
    __syncthreads();

    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;
    if (tid >= idx_count) return;

    uint64_t idx = idx_base + tid;

    uint8_t pw[14];
    index_to_password(idx, pw);

    // passraw: key[16] = pw[14] || 0x00 0x00. SIN MD5 ni hexify.
    uint8_t key[16];
    #pragma unroll
    for (int i = 0; i < 14; ++i) key[i] = pw[i];
    key[14] = 0;
    key[15] = 0;

    uint32_t rk[44];
    aes128_set_key_with_tables(key, rk, s_td0, s_sbox);

    // ECB: pt_real = pt_block (sin XOR de IV).
    uint8_t* out = pt_out + tid * 16;
    aes128_decrypt_block_ptr(rk, s_ct, out,
        s_td0, s_td1, s_td2, s_td3, s_isbox);
}
