// brute_passraw_aes128_ecb.cu — kernel ACTIVO D-035 (cifraronline.com construction).
//
// Construcción real verificada bit-exact contra cifraronline.com:
//
//   key  = password.encode() + b'\x00' * (16 - len(password.encode()))
//          ASCII directo + null pad hasta 16 B. SIN MD5, SIN hexify.
//   mode = AES-128-ECB        (10 rondas, 11 round keys = rk[44])
//   pad  = NULL                (sobre el message = plaintext + md5_hex(plaintext))
//
// En el reto, los 14 B de password caben siempre exactos en 16 B (key[14]=0,
// key[15]=0). El "Hash: MD5" de la web cifraronline se refiere al MD5 del
// PLAINTEXT que se concatena al final como integrity check, NO a la KDF de
// la clave. Confirmado experimentalmente: vector
// `(.aAaaeeii1452., "Leonardo da Vinci\\n\\nLeonardo da Vinci es muy crack 1452.")`
// produce ciphertext bit-exact contra pycryptodome.
//
// Cada thread:
//   1) idx = idx_base + (gid stride loop)
//   2) password ← index_to_password(idx)            // 14 B ASCII
//   3) key[16]  ← password[0..14] || 0x00 0x00      // sin MD5 ni hexify
//   4) rk[44]   ← AES-128 key schedule (con InvMixColumns vía Td0)
//   5) pt0[16]  ← AES-128 decrypt(ct_block_0, rk)   // ECB: sin XOR de IV
//   6) si pt0 == "Leonardo da Vinc" → emit hit
//
// CPU valida después: prefijo-32 (LF o CRLF) + verifica MD5(plaintext_clean)
// vs los últimos 32 chars del plaintext descifrado (D-035 validate_hit).
//
// PERF heredado de Fase 6 (D-022, D-023, D-024):
//   - __launch_bounds__(128, 8): AES-128 (rk[44] vs rk[60] de AES-256) tiene
//     menos register pressure ⇒ apuntamos a más blocks/SM. Recalibra con
//     `nvcc -ptxas-options=-v` si añades complejidad al hot path.
//   - QC_N_PER_THREAD = 8 candidatas por thread (stride loop interno).
//   - QC_MAX_GRID_BLOCKS = 4096 cap absoluto.
//   - Td0..Td3 + INV_SBOX + SBOX en __shared__ por block (cooperativo).

#include <stdint.h>
#include "gen.cuh"
#include "aes.cuh"

struct DeviceHit {
    uint64_t idx;
};

#ifndef QC_BLOCK_DIM
#define QC_BLOCK_DIM 128
#endif
#ifndef QC_BLOCKS_PER_SM
#define QC_BLOCKS_PER_SM 8
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

        // 2) key[16] = pw[14] || 0x00 0x00 (NUNCA MD5 — passraw + null pad).
        uint8_t key[16];
        #pragma unroll
        for (int i = 0; i < 14; ++i) {
            key[i] = pw[i];
        }
        key[14] = 0;
        key[15] = 0;

        // 3) AES-128 key schedule (InvMixColumns vía Td0, D-023).
        uint32_t rk[44];
        aes128_set_key_with_tables(key, rk, s_td0, s_sbox);

        // 4) AES-128 decrypt single block.
        uint8_t pt_block[16];
        aes128_decrypt_block_ptr(rk, s_ct, pt_block,
            s_td0, s_td1, s_td2, s_td3, s_isbox);

        // 5) ECB: NO se XORea con IV. Comparación unrolled vs
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
