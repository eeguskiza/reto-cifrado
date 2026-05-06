// dump_pt_block0_coop.cu — kernel diagnóstico (D-030).
//
// Mismo contrato externo que `dump_pt_block0` (legacy): para cada idx en
// [idx_base, idx_base+idx_count), produce los primeros 16 B del plaintext
// bajo md5hex_full + AES-256-ECB.
//
// Internamente usa el path cooperativo: el grupo (4 threads) procesa una
// candidata, líder hace KDF+key schedule, los 4 threads leen su columna
// de rk[60] y hacen `aes256_decrypt_block_coop` (helper compartido con
// `brute_md5hex_aes256_ecb_coop.cu`).
//
// Validación bit-exact en `tests/coop_kernel_parity.rs`: 1.000.000 idx
// vs `reference::decrypt_ecb_raw` (CPU) y vs el legacy `dump_pt_block0`.

#include <stdint.h>
#include "gen.cuh"
#include "md5.cuh"
#include "aes.cuh"
#include "aes_coop.cuh"

#ifndef QC_DUMP_BLOCK_DIM_COOP
#define QC_DUMP_BLOCK_DIM_COOP 128
#endif
#ifndef QC_DUMP_BLOCKS_PER_SM_COOP
#define QC_DUMP_BLOCKS_PER_SM_COOP 5
#endif

#define QC_DUMP_GROUPS_PER_BLOCK (QC_DUMP_BLOCK_DIM_COOP / 4)
#define QC_DUMP_GROUPS_PER_WARP  8

extern "C" __global__
__launch_bounds__(QC_DUMP_BLOCK_DIM_COOP, QC_DUMP_BLOCKS_PER_SM_COOP)
void dump_pt_block0_coop(
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
    __shared__ uint32_t s_rk[QC_DUMP_GROUPS_PER_BLOCK][60];

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

    const int tid_in_block  = (int)threadIdx.x;
    const int lane          = tid_in_block & 31;
    const int warp_in_block = tid_in_block >> 5;
    const int group_in_warp = lane >> 2;
    const int col           = lane & 3;
    const int group_in_blk  = warp_in_block * QC_DUMP_GROUPS_PER_WARP + group_in_warp;

    const uint64_t total_groups = (uint64_t)gridDim.x * (uint64_t)QC_DUMP_GROUPS_PER_BLOCK;
    const uint64_t group_global = (uint64_t)blockIdx.x * (uint64_t)QC_DUMP_GROUPS_PER_BLOCK
                                + (uint64_t)group_in_blk;

    const uint32_t my_ct_col = aes_get_u32_le(s_ct + col * 4);

    for (uint64_t pos = group_global; pos < idx_count; pos += total_groups) {
        const uint64_t idx = idx_base + pos;

        if (col == 0) {
            uint8_t pw[14];
            index_to_password(idx, pw);

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

            uint32_t* my_rk = &s_rk[group_in_blk][0];
            aes256_set_key_with_tables(key, my_rk, s_td0, s_sbox);
        }
        __syncwarp(0xffffffffu);

        uint32_t rk_col[15];
        #pragma unroll
        for (int r = 0; r < 15; ++r) {
            rk_col[r] = s_rk[group_in_blk][r * 4 + col];
        }

        const uint32_t state = aes256_decrypt_block_coop(
            my_ct_col, rk_col, col,
            s_td0, s_td1, s_td2, s_td3, s_isbox);

        // Cada thread escribe su columna (4 bytes) al output del idx.
        uint8_t* out = pt_out + pos * 16 + (uint64_t)col * 4;
        aes_put_u32_le(state, out);
    }
}
