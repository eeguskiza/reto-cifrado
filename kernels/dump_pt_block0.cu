// dump_pt_block0.cu — kernel de diagnóstico SOLO para tests.
//
// Tras D-029: produce el plaintext de los primeros 16 B del CT objetivo
// bajo la única configuración activa:
//
//   key = MD5(pw_utf8).hexdigest().encode("ascii")  // 32 B AES-256
//   AES-256-ECB                                       // sin IV
//
// Reutiliza las mismas primitivas (md5_compute, aes256_decrypt_block_ptr)
// que el brute_kernel monolítico, así que si este kernel produce los
// plaintexts correctos byte-a-byte, el de barrido también.
//
// Validación bit-exact frente a `reference::decrypt_ecb_raw` de CPU
// vive en `tests/optimized_kernel_parity.rs`.

#include <stdint.h>
#include "gen.cuh"
#include "md5.cuh"
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

    // md5hex_full: raw → ASCII hex lowercase, 32 B.
    uint8_t md5_raw[16];
    md5_compute(pw, 14, md5_raw);
    uint8_t key[32];
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        uint8_t hi = (uint8_t)((md5_raw[i] >> 4) & 0xfu);
        uint8_t lo = (uint8_t)(md5_raw[i] & 0xfu);
        key[i * 2 + 0] = (uint8_t)((hi < 10u) ? ('0' + hi) : ('a' + hi - 10u));
        key[i * 2 + 1] = (uint8_t)((lo < 10u) ? ('0' + lo) : ('a' + lo - 10u));
    }

    uint32_t rk[60];
    aes256_set_key_with_tables(key, rk, s_td0, s_sbox);

    // ECB: pt_real = pt_block (sin XOR de IV).
    uint8_t* out = pt_out + tid * 16;
    aes256_decrypt_block_ptr(rk, s_ct, out,
        s_td0, s_td1, s_td2, s_td3, s_isbox);
}
