// aes_coop.cuh — AES-256 decrypt cooperativo intra-warp (D-030).
//
// Modelo: 4 threads cooperan sobre 1 candidata. Cada uno posee una columna
// de 32 bits del estado AES (col_id ∈ {0,1,2,3}). Los 4 threads del grupo
// son lanes consecutivas dentro del warp: lane = group_in_warp*4 + col.
//
// La función cooperativa NO computa el key schedule — recibe directamente
// rk_col[15] = la columna del thread de cada round key (rounds 0..14).
// Eso permite que el caller (brute_kernel_coop o dump_pt_block0_coop)
// haga el schedule en el thread líder a __shared__ y los followers carguen
// solo su columna a registros (15 dwords/thread vs 60 dwords del legacy).
//
// __shfl_sync con width=4 divide el warp en sub-warps de 4 lanes. Dentro
// de cada sub-warp, srcLane∈[0,3] selecciona la columna fuente para
// implementar InvShiftRows (que cruza columnas en AES decrypt).
//
// Validación bit-exact (1M idx) en `tests/coop_kernel_parity.rs`.

#pragma once

#include <stdint.h>
#include "aes.cuh"

// `state` (input/output) = mi columna del estado AES (32 bits LE).
// Recibe `my_ct_col` (mi columna del ciphertext, ya XORed con rk_col[0]
// fuera, o se pasa raw y se hace dentro). En esta API, el caller pasa
// `my_ct_col` raw y el primer XOR se hace dentro.
__forceinline__ __device__ uint32_t aes256_decrypt_block_coop(
    uint32_t my_ct_col,
    const uint32_t rk_col[15],
    int col,
    const uint32_t* __restrict__ s_td0,
    const uint32_t* __restrict__ s_td1,
    const uint32_t* __restrict__ s_td2,
    const uint32_t* __restrict__ s_td3,
    const uint8_t*  __restrict__ s_isbox
) {
    // Round 0: AddRoundKey directo.
    uint32_t state = my_ct_col ^ rk_col[0];

    // Rondas 1..13: InvShiftRows + InvSubBytes + InvMixColumns + AddRoundKey,
    // todo plegado en las T-tables Td0..Td3.
    //
    // Para la salida de columna c necesitamos:
    //   byte 0 de la columna  c       (propia)
    //   byte 1 de la columna (c+3)%4  (shfl srcLane = (col+3)&3)
    //   byte 2 de la columna (c+2)%4
    //   byte 3 de la columna (c+1)%4
    #pragma unroll
    for (int r = 1; r <= 13; ++r) {
        uint32_t b0_src = state;
        uint32_t b1_src = __shfl_sync(0xffffffffu, state, (col + 3) & 3, 4);
        uint32_t b2_src = __shfl_sync(0xffffffffu, state, (col + 2) & 3, 4);
        uint32_t b3_src = __shfl_sync(0xffffffffu, state, (col + 1) & 3, 4);
        state = s_td0[(b0_src      ) & 0xff]
              ^ s_td1[(b1_src >>  8) & 0xff]
              ^ s_td2[(b2_src >> 16) & 0xff]
              ^ s_td3[(b3_src >> 24) & 0xff]
              ^ rk_col[r];
    }

    // Ronda 14 (final): InvShiftRows + InvSubBytes + AddRoundKey, sin
    // InvMixColumns (no Td-tables, sí inv-sbox).
    {
        uint32_t b0_src = state;
        uint32_t b1_src = __shfl_sync(0xffffffffu, state, (col + 3) & 3, 4);
        uint32_t b2_src = __shfl_sync(0xffffffffu, state, (col + 2) & 3, 4);
        uint32_t b3_src = __shfl_sync(0xffffffffu, state, (col + 1) & 3, 4);
        state = ((uint32_t)s_isbox[(b0_src      ) & 0xff])
             | ((uint32_t)s_isbox[(b1_src >>  8) & 0xff] <<  8)
             | ((uint32_t)s_isbox[(b2_src >> 16) & 0xff] << 16)
             | ((uint32_t)s_isbox[(b3_src >> 24) & 0xff] << 24);
        state ^= rk_col[14];
    }
    return state;
}
