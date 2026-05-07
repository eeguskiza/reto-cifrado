// brute_md5hex_aes256_ecb.cu — kernel monolítico tras D-029.
//
// Configuración cableada (no hay parametrización por KDF/IV/MODE):
//
//   key  = MD5(pw_utf8).hexdigest().encode("ascii")  // 32 B ASCII = AES-256
//   mode = AES-256-ECB                              // sin IV, sin XOR
//   pad  = PKCS7                                    // validado en CPU sobre el hit
//
// Cada thread:
//   1) idx = idx_base + (gid stride loop)
//   2) password ← index_to_password(idx)            // 14 B ASCII
//   3) raw[16] ← MD5(password)
//   4) key[32] ← raw → ASCII hex lowercase (in-register)
//   5) rk[60]  ← AES-256 key schedule (con InvMixColumns vía Td0)
//   6) pt0[16] ← AES-256 decrypt(ct_block_0, rk)    // ECB: sin XOR de IV
//   7) si pt0 == "Leonardo da Vinc" → emit hit
//
// PERF heredado de Fase 6 (D-022, D-023, D-024):
//   - __launch_bounds__(128, 6) para fijar 80 regs/thread, 768 threads/SM.
//   - QC_N_PER_THREAD = 8 candidatas por thread (stride loop interno).
//   - QC_MAX_GRID_BLOCKS = 4096 cap absoluto.
//   - Td0..Td3 + INV_SBOX + SBOX en __shared__ por block (cooperativo).
//
// Justificación D-029: tras eliminar las 13 KDFs alternativas, el
// dispatch interno desaparece, hay un único PTX (vs 14 antes), y se
// elimina la rama IV (ECB). Esperamos +10–20 % vs el kernel
// parametrizado equivalente.

#include <stdint.h>
#include "gen.cuh"
#include "md5.cuh"
#include "aes.cuh"

struct DeviceHit {
    uint64_t idx;
};

// ---------- launch bounds (heredado de Fase 6) ----------
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
    const uint8_t* __restrict__ ct_block_0,    // 16 B
    DeviceHit* __restrict__ hits_out,
    uint32_t* __restrict__ hit_counter,
    uint32_t hits_capacity
) {
    // ---------- copia cooperativa de tablas a __shared__ ----------
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

    // ---------- hot loop ----------
    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;
    uint64_t total_threads = (uint64_t)gridDim.x * (uint64_t)blockDim.x;

    for (uint64_t pos = tid; pos < idx_count; pos += total_threads) {
        uint64_t idx = idx_base + pos;

        // 1) password in-device (14 B ASCII).
        uint8_t pw[14];
        index_to_password(idx, pw);

        // 2) MD5(pw) → 16 B raw.
        uint8_t md5_raw[16];
        md5_compute(pw, 14, md5_raw);

        // 3) raw → ASCII hex lowercase, 32 B (clave AES-256).
        uint8_t key[32];
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            uint8_t hi = (uint8_t)((md5_raw[i] >> 4) & 0xfu);
            uint8_t lo = (uint8_t)(md5_raw[i] & 0xfu);
            key[i * 2 + 0] = (uint8_t)((hi < 10u) ? ('0' + hi) : ('a' + hi - 10u));
            key[i * 2 + 1] = (uint8_t)((lo < 10u) ? ('0' + lo) : ('a' + lo - 10u));
        }

        // 4) AES-256 key schedule (InvMixColumns vía Td0, D-023).
        uint32_t rk[60];
        aes256_set_key_with_tables(key, rk, s_td0, s_sbox);

        // 5) AES-256 decrypt single block.
        uint8_t pt_block[16];
        aes256_decrypt_block_ptr(rk, s_ct, pt_block,
            s_td0, s_td1, s_td2, s_td3, s_isbox);

        // 6) ECB: NO se XORea con IV. Comparación unrolled vs
        //    "Leonardo da Vinc" (16 B, 4 × uint32_t LE).
        uint32_t p0 = aes_get_u32_le(pt_block +  0);
        uint32_t p1 = aes_get_u32_le(pt_block +  4);
        uint32_t p2 = aes_get_u32_le(pt_block +  8);
        uint32_t p3 = aes_get_u32_le(pt_block + 12);

        uint32_t a = p0 ^ 0x6E6F654Cu;  // "Leon"
        uint32_t b = p1 ^ 0x6F647261u;  // "ardo"
        uint32_t c = p2 ^ 0x20616420u;  // " da "
        uint32_t d = p3 ^ 0x636E6956u;  // "Vinc"

        if ((a | b | c | d) == 0u) {
            uint32_t slot = atomicAdd(hit_counter, 1u);
            if (slot < hits_capacity) {
                hits_out[slot].idx = idx;
            }
        }
    }
}
