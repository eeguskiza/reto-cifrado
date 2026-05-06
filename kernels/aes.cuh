// aes.cuh — AES-128 y AES-256 device, optimizados para decrypt single-block.
//
// API pública (para tests sueltos en kernels/aes_test.cu):
//   __device__ void aes128_set_key(const uint8_t key[16], uint32_t rk[44])
//   __device__ void aes128_decrypt_block(const uint32_t rk[44], const uint8_t in[16], uint8_t out[16])
//   __device__ void aes256_set_key(const uint8_t key[32], uint32_t rk[60])
//   __device__ void aes256_decrypt_block(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16])
//
// API "interna" para el hot path del barrido en brute.cu:
//   _param variants que aceptan punteros a las T-tables y al inv-sbox.
//   brute.cu copia las tablas desde __constant__ a __shared__ una vez por
//   block y llama a esta variante para que las 9 (o 13) rondas de cada
//   thread accedan a __shared__ — banco-paralelizable — en lugar de
//   __constant__ — single-port broadcast que serializa cuando los hilos
//   acceden a direcciones distintas.
//
// PERF: ver DECISIONS.md D-009 para la justificación medida.
//
// Validado contra NIST FIPS-197 Appendix C.1 / C.3 en tests/aes_fips197.rs.

#pragma once

#include <stdint.h>
#include "aes_tables.cuh"

// ---------- helpers ----------

__forceinline__ __device__ uint32_t aes_get_u32_le(const uint8_t* p) {
    return ((uint32_t)p[0])
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

__forceinline__ __device__ void aes_put_u32_le(uint32_t v, uint8_t* p) {
    p[0] = (uint8_t)(v >>  0);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

__forceinline__ __device__ uint32_t aes_sub_word(uint32_t w) {
    return  (uint32_t)QC_AES_SBOX[ w        & 0xff]
         | ((uint32_t)QC_AES_SBOX[(w >>  8) & 0xff] <<  8)
         | ((uint32_t)QC_AES_SBOX[(w >> 16) & 0xff] << 16)
         | ((uint32_t)QC_AES_SBOX[(w >> 24) & 0xff] << 24);
}

__forceinline__ __device__ uint32_t aes_rot_word(uint32_t w) {
    return (w >> 8) | (w << 24);
}

__forceinline__ __device__ uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    #pragma unroll
    for (int i = 0; i < 8; ++i) {
        if (b & 1u) r ^= a;
        uint8_t hi = a & 0x80u;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1bu;
        b = (uint8_t)(b >> 1);
    }
    return r;
}

__forceinline__ __device__ uint32_t aes_inv_mix_column(uint32_t s) {
    uint8_t b0 = (uint8_t)(s >>  0);
    uint8_t b1 = (uint8_t)(s >>  8);
    uint8_t b2 = (uint8_t)(s >> 16);
    uint8_t b3 = (uint8_t)(s >> 24);
    uint8_t r0 = aes_gmul(b0, 0x0e) ^ aes_gmul(b1, 0x0b) ^ aes_gmul(b2, 0x0d) ^ aes_gmul(b3, 0x09);
    uint8_t r1 = aes_gmul(b0, 0x09) ^ aes_gmul(b1, 0x0e) ^ aes_gmul(b2, 0x0b) ^ aes_gmul(b3, 0x0d);
    uint8_t r2 = aes_gmul(b0, 0x0d) ^ aes_gmul(b1, 0x09) ^ aes_gmul(b2, 0x0e) ^ aes_gmul(b3, 0x0b);
    uint8_t r3 = aes_gmul(b0, 0x0b) ^ aes_gmul(b1, 0x0d) ^ aes_gmul(b2, 0x09) ^ aes_gmul(b3, 0x0e);
    return (uint32_t)r0
         | ((uint32_t)r1 <<  8)
         | ((uint32_t)r2 << 16)
         | ((uint32_t)r3 << 24);
}

// PERF: variante rápida de InvMixColumns que reutiliza las T-tables Td0
// (que ya contienen las cuatro mul-by-{0x0e, 0x09, 0x0d, 0x0b} empaquetadas)
// + SBOX para invertir el InvSBox que Td0 aplica internamente. Reemplaza
// 16 invocaciones de `aes_gmul` (8 iteraciones cada una) por 4 lookups en
// SBOX + 4 en Td0 + permutación de bytes. Las tablas pueden venir de
// __constant__ (key schedule fuera del hot loop) o __shared__ (uso
// in-loop). Identidad usada: Td0[SBOX[b]] = (b·0e, b·09, b·0d, b·0b) LE.
__forceinline__ __device__ uint32_t aes_inv_mix_column_via_td0(
    uint32_t s,
    const uint32_t* __restrict__ td0,
    const uint8_t*  __restrict__ sbox
) {
    uint8_t b0 = (uint8_t)(s >>  0);
    uint8_t b1 = (uint8_t)(s >>  8);
    uint8_t b2 = (uint8_t)(s >> 16);
    uint8_t b3 = (uint8_t)(s >> 24);
    uint32_t t0 = td0[sbox[b0]];
    uint32_t t1 = td0[sbox[b1]];
    uint32_t t2 = td0[sbox[b2]];
    uint32_t t3 = td0[sbox[b3]];
    // Bytes: t_i = (b_i·0e, b_i·09, b_i·0d, b_i·0b) en LE.
    uint8_t c0 = (uint8_t)(((t0      ) ^ (t1 >> 24) ^ (t2 >> 16) ^ (t3 >>  8)) & 0xffu);
    uint8_t c1 = (uint8_t)(((t0 >>  8) ^ (t1      ) ^ (t2 >> 24) ^ (t3 >> 16)) & 0xffu);
    uint8_t c2 = (uint8_t)(((t0 >> 16) ^ (t1 >>  8) ^ (t2      ) ^ (t3 >> 24)) & 0xffu);
    uint8_t c3 = (uint8_t)(((t0 >> 24) ^ (t1 >> 16) ^ (t2 >>  8) ^ (t3      )) & 0xffu);
    return (uint32_t)c0
         | ((uint32_t)c1 <<  8)
         | ((uint32_t)c2 << 16)
         | ((uint32_t)c3 << 24);
}

// ---------- AES-128 schedule ----------

__forceinline__ __device__ void aes128_set_key_with_tables(
    const uint8_t key[16],
    uint32_t rk[44],
    const uint32_t* __restrict__ td0,
    const uint8_t*  __restrict__ sbox
) {
    rk[0] = aes_get_u32_le(key +  0);
    rk[1] = aes_get_u32_le(key +  4);
    rk[2] = aes_get_u32_le(key +  8);
    rk[3] = aes_get_u32_le(key + 12);

    #pragma unroll
    for (int i = 4; i < 44; ++i) {
        uint32_t temp = rk[i - 1];
        if ((i & 3) == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ (uint32_t)QC_AES_RCON[(i >> 2) - 1];
        }
        rk[i] = rk[i - 4] ^ temp;
    }

    #pragma unroll
    for (int i = 0; i < 5; ++i) {
        int j = 40 - 4 * i;
        if (i * 4 < j) {
            uint32_t t0 = rk[i*4 + 0]; rk[i*4 + 0] = rk[j + 0]; rk[j + 0] = t0;
            uint32_t t1 = rk[i*4 + 1]; rk[i*4 + 1] = rk[j + 1]; rk[j + 1] = t1;
            uint32_t t2 = rk[i*4 + 2]; rk[i*4 + 2] = rk[j + 2]; rk[j + 2] = t2;
            uint32_t t3 = rk[i*4 + 3]; rk[i*4 + 3] = rk[j + 3]; rk[j + 3] = t3;
        }
    }
    // PERF (D-023): tras Fase 6, con launch_bounds + amortización de
    // candidatas por thread la ruta SBOX→Td0 (5 instr/inv_mix con tablas
    // en __shared__) gana al gmul-loop unrolled (~130 instr/inv_mix puro
    // ALU). Cuando el bottleneck era register pressure ganaba el ALU
    // (D-009); con occupancy mayor el cost shift es a favor de menos
    // instrucciones. 36 calls × ~125 instr ahorradas por candidata ≈
    // 4500 instr menos por candidata.
    #pragma unroll
    for (int idx = 4; idx < 40; ++idx) {
        rk[idx] = aes_inv_mix_column_via_td0(rk[idx], td0, sbox);
    }
}

__forceinline__ __device__ void aes128_set_key(const uint8_t key[16], uint32_t rk[44]) {
    aes128_set_key_with_tables(key, rk, QC_AES_TD0, QC_AES_SBOX);
}

// ---------- AES-256 schedule ----------

// ---------- AES-192 schedule ----------
// 192 bits = 6 words, Nk=6, Nr=12 → 13 round keys × 4 = 52 words.

__forceinline__ __device__ void aes192_set_key_with_tables(
    const uint8_t key[24],
    uint32_t rk[52],
    const uint32_t* __restrict__ td0,
    const uint8_t*  __restrict__ sbox
) {
    rk[0] = aes_get_u32_le(key +  0);
    rk[1] = aes_get_u32_le(key +  4);
    rk[2] = aes_get_u32_le(key +  8);
    rk[3] = aes_get_u32_le(key + 12);
    rk[4] = aes_get_u32_le(key + 16);
    rk[5] = aes_get_u32_le(key + 20);

    #pragma unroll
    for (int i = 6; i < 52; ++i) {
        uint32_t temp = rk[i - 1];
        if (i % 6 == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ (uint32_t)QC_AES_RCON[(i / 6) - 1];
        }
        rk[i] = rk[i - 6] ^ temp;
    }

    // Reverse en bloques de 4 words; total = 52 words = 13 rondas. Mid 1..11.
    #pragma unroll
    for (int i = 0; i < 6; ++i) {
        int j = 48 - 4 * i;
        if (i * 4 < j) {
            uint32_t t0 = rk[i*4 + 0]; rk[i*4 + 0] = rk[j + 0]; rk[j + 0] = t0;
            uint32_t t1 = rk[i*4 + 1]; rk[i*4 + 1] = rk[j + 1]; rk[j + 1] = t1;
            uint32_t t2 = rk[i*4 + 2]; rk[i*4 + 2] = rk[j + 2]; rk[j + 2] = t2;
            uint32_t t3 = rk[i*4 + 3]; rk[i*4 + 3] = rk[j + 3]; rk[j + 3] = t3;
        }
    }
    #pragma unroll
    for (int idx = 4; idx < 48; ++idx) {
        rk[idx] = aes_inv_mix_column_via_td0(rk[idx], td0, sbox);
    }
}

__forceinline__ __device__ void aes192_set_key(const uint8_t key[24], uint32_t rk[52]) {
    aes192_set_key_with_tables(key, rk, QC_AES_TD0, QC_AES_SBOX);
}

__forceinline__ __device__ void aes256_set_key_with_tables(
    const uint8_t key[32],
    uint32_t rk[60],
    const uint32_t* __restrict__ td0,
    const uint8_t*  __restrict__ sbox
) {
    rk[0] = aes_get_u32_le(key +  0);
    rk[1] = aes_get_u32_le(key +  4);
    rk[2] = aes_get_u32_le(key +  8);
    rk[3] = aes_get_u32_le(key + 12);
    rk[4] = aes_get_u32_le(key + 16);
    rk[5] = aes_get_u32_le(key + 20);
    rk[6] = aes_get_u32_le(key + 24);
    rk[7] = aes_get_u32_le(key + 28);

    #pragma unroll
    for (int i = 8; i < 60; ++i) {
        uint32_t temp = rk[i - 1];
        if ((i & 7) == 0) {
            temp = aes_sub_word(aes_rot_word(temp)) ^ (uint32_t)QC_AES_RCON[(i >> 3) - 1];
        } else if ((i & 7) == 4) {
            temp = aes_sub_word(temp);
        }
        rk[i] = rk[i - 8] ^ temp;
    }

    #pragma unroll
    for (int i = 0; i < 7; ++i) {
        int j = 56 - 4 * i;
        if (i * 4 < j) {
            uint32_t t0 = rk[i*4 + 0]; rk[i*4 + 0] = rk[j + 0]; rk[j + 0] = t0;
            uint32_t t1 = rk[i*4 + 1]; rk[i*4 + 1] = rk[j + 1]; rk[j + 1] = t1;
            uint32_t t2 = rk[i*4 + 2]; rk[i*4 + 2] = rk[j + 2]; rk[j + 2] = t2;
            uint32_t t3 = rk[i*4 + 3]; rk[i*4 + 3] = rk[j + 3]; rk[j + 3] = t3;
        }
    }
    #pragma unroll
    for (int idx = 4; idx < 56; ++idx) {
        rk[idx] = aes_inv_mix_column_via_td0(rk[idx], td0, sbox);
    }
}

__forceinline__ __device__ void aes256_set_key(const uint8_t key[32], uint32_t rk[60]) {
    aes256_set_key_with_tables(key, rk, QC_AES_TD0, QC_AES_SBOX);
}

// ---------- decrypt block — versión paramétrica con punteros a tablas ----------
// Usada por brute.cu con tablas en __shared__. La macro espera punteros llamados
// `td0..td3` e `isbox` definidos en el scope de la llamada.

#define AES_DEC_ROUND_PTR(rk_off, td0, td1, td2, td3) \
    do { \
        uint32_t t0_ = (td0)[(s0 >>  0) & 0xff] \
                     ^ (td1)[(s3 >>  8) & 0xff] \
                     ^ (td2)[(s2 >> 16) & 0xff] \
                     ^ (td3)[(s1 >> 24) & 0xff] \
                     ^ rk[(rk_off) + 0]; \
        uint32_t t1_ = (td0)[(s1 >>  0) & 0xff] \
                     ^ (td1)[(s0 >>  8) & 0xff] \
                     ^ (td2)[(s3 >> 16) & 0xff] \
                     ^ (td3)[(s2 >> 24) & 0xff] \
                     ^ rk[(rk_off) + 1]; \
        uint32_t t2_ = (td0)[(s2 >>  0) & 0xff] \
                     ^ (td1)[(s1 >>  8) & 0xff] \
                     ^ (td2)[(s0 >> 16) & 0xff] \
                     ^ (td3)[(s3 >> 24) & 0xff] \
                     ^ rk[(rk_off) + 2]; \
        uint32_t t3_ = (td0)[(s3 >>  0) & 0xff] \
                     ^ (td1)[(s2 >>  8) & 0xff] \
                     ^ (td2)[(s1 >> 16) & 0xff] \
                     ^ (td3)[(s0 >> 24) & 0xff] \
                     ^ rk[(rk_off) + 3]; \
        s0 = t0_; s1 = t1_; s2 = t2_; s3 = t3_; \
    } while (0)

__forceinline__ __device__ void aes_dec_final_round_ptr(
    uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
    const uint32_t* __restrict__ rk_final,
    uint8_t out[16],
    const uint8_t* __restrict__ isbox
) {
    uint32_t o0 = ((uint32_t)isbox[(s0 >>  0) & 0xff])
                | ((uint32_t)isbox[(s3 >>  8) & 0xff] <<  8)
                | ((uint32_t)isbox[(s2 >> 16) & 0xff] << 16)
                | ((uint32_t)isbox[(s1 >> 24) & 0xff] << 24);
    o0 ^= rk_final[0];
    uint32_t o1 = ((uint32_t)isbox[(s1 >>  0) & 0xff])
                | ((uint32_t)isbox[(s0 >>  8) & 0xff] <<  8)
                | ((uint32_t)isbox[(s3 >> 16) & 0xff] << 16)
                | ((uint32_t)isbox[(s2 >> 24) & 0xff] << 24);
    o1 ^= rk_final[1];
    uint32_t o2 = ((uint32_t)isbox[(s2 >>  0) & 0xff])
                | ((uint32_t)isbox[(s1 >>  8) & 0xff] <<  8)
                | ((uint32_t)isbox[(s0 >> 16) & 0xff] << 16)
                | ((uint32_t)isbox[(s3 >> 24) & 0xff] << 24);
    o2 ^= rk_final[2];
    uint32_t o3 = ((uint32_t)isbox[(s3 >>  0) & 0xff])
                | ((uint32_t)isbox[(s2 >>  8) & 0xff] <<  8)
                | ((uint32_t)isbox[(s1 >> 16) & 0xff] << 16)
                | ((uint32_t)isbox[(s0 >> 24) & 0xff] << 24);
    o3 ^= rk_final[3];

    aes_put_u32_le(o0, out +  0);
    aes_put_u32_le(o1, out +  4);
    aes_put_u32_le(o2, out +  8);
    aes_put_u32_le(o3, out + 12);
}

__forceinline__ __device__ void aes128_decrypt_block_ptr(
    const uint32_t rk[44],
    const uint8_t in[16],
    uint8_t out[16],
    const uint32_t* __restrict__ td0,
    const uint32_t* __restrict__ td1,
    const uint32_t* __restrict__ td2,
    const uint32_t* __restrict__ td3,
    const uint8_t*  __restrict__ isbox
) {
    uint32_t s0 = aes_get_u32_le(in +  0) ^ rk[0];
    uint32_t s1 = aes_get_u32_le(in +  4) ^ rk[1];
    uint32_t s2 = aes_get_u32_le(in +  8) ^ rk[2];
    uint32_t s3 = aes_get_u32_le(in + 12) ^ rk[3];

    AES_DEC_ROUND_PTR( 4, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR( 8, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(12, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(16, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(20, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(24, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(28, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(32, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(36, td0, td1, td2, td3);

    aes_dec_final_round_ptr(s0, s1, s2, s3, &rk[40], out, isbox);
}

__forceinline__ __device__ void aes192_decrypt_block_ptr(
    const uint32_t rk[52],
    const uint8_t in[16],
    uint8_t out[16],
    const uint32_t* __restrict__ td0,
    const uint32_t* __restrict__ td1,
    const uint32_t* __restrict__ td2,
    const uint32_t* __restrict__ td3,
    const uint8_t*  __restrict__ isbox
) {
    uint32_t s0 = aes_get_u32_le(in +  0) ^ rk[0];
    uint32_t s1 = aes_get_u32_le(in +  4) ^ rk[1];
    uint32_t s2 = aes_get_u32_le(in +  8) ^ rk[2];
    uint32_t s3 = aes_get_u32_le(in + 12) ^ rk[3];

    AES_DEC_ROUND_PTR( 4, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR( 8, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(12, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(16, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(20, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(24, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(28, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(32, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(36, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(40, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(44, td0, td1, td2, td3);

    aes_dec_final_round_ptr(s0, s1, s2, s3, &rk[48], out, isbox);
}

__forceinline__ __device__ void aes256_decrypt_block_ptr(
    const uint32_t rk[60],
    const uint8_t in[16],
    uint8_t out[16],
    const uint32_t* __restrict__ td0,
    const uint32_t* __restrict__ td1,
    const uint32_t* __restrict__ td2,
    const uint32_t* __restrict__ td3,
    const uint8_t*  __restrict__ isbox
) {
    uint32_t s0 = aes_get_u32_le(in +  0) ^ rk[0];
    uint32_t s1 = aes_get_u32_le(in +  4) ^ rk[1];
    uint32_t s2 = aes_get_u32_le(in +  8) ^ rk[2];
    uint32_t s3 = aes_get_u32_le(in + 12) ^ rk[3];

    AES_DEC_ROUND_PTR( 4, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR( 8, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(12, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(16, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(20, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(24, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(28, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(32, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(36, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(40, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(44, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(48, td0, td1, td2, td3);
    AES_DEC_ROUND_PTR(52, td0, td1, td2, td3);

    aes_dec_final_round_ptr(s0, s1, s2, s3, &rk[56], out, isbox);
}

// ---------- decrypt block — wrapper público que usa __constant__ ----------
// Usado por aes_test.cu (test FIPS-197). En el hot path real (brute.cu) se
// llama directamente a la versión _ptr con tablas en __shared__.

__forceinline__ __device__ void aes128_decrypt_block(
    const uint32_t rk[44],
    const uint8_t in[16],
    uint8_t out[16]
) {
    aes128_decrypt_block_ptr(rk, in, out,
        QC_AES_TD0, QC_AES_TD1, QC_AES_TD2, QC_AES_TD3, QC_AES_INV_SBOX);
}

__forceinline__ __device__ void aes192_decrypt_block(
    const uint32_t rk[52],
    const uint8_t in[16],
    uint8_t out[16]
) {
    aes192_decrypt_block_ptr(rk, in, out,
        QC_AES_TD0, QC_AES_TD1, QC_AES_TD2, QC_AES_TD3, QC_AES_INV_SBOX);
}

__forceinline__ __device__ void aes256_decrypt_block(
    const uint32_t rk[60],
    const uint8_t in[16],
    uint8_t out[16]
) {
    aes256_decrypt_block_ptr(rk, in, out,
        QC_AES_TD0, QC_AES_TD1, QC_AES_TD2, QC_AES_TD3, QC_AES_INV_SBOX);
}
