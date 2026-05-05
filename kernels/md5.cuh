// md5.cuh — MD5 device (RFC 1321), single-pass de longitud arbitraria.
//
// API:
//   __device__ void md5_compute(const uint8_t* data, uint32_t len, uint8_t out[16])
//   __device__ void md5_compute_md5(const uint8_t in[16], uint8_t out[16])
//
// Sin allocación dinámica device, sin malloc, sin printf.
// Validado contra los 7 vectores estándar del RFC 1321 en
// tests/md5_rfc1321.rs.

#pragma once

#include <stdint.h>

// ---------- helpers ----------

__forceinline__ __device__ uint32_t md5_rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32u - n));
}

// Per-round constants (RFC 1321 §3.4).
__device__ __constant__ uint32_t QC_MD5_K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

// Shifts per round.
__device__ __constant__ uint32_t QC_MD5_S[64] = {
    7,12,17,22,  7,12,17,22,  7,12,17,22,  7,12,17,22,
    5, 9,14,20,  5, 9,14,20,  5, 9,14,20,  5, 9,14,20,
    4,11,16,23,  4,11,16,23,  4,11,16,23,  4,11,16,23,
    6,10,15,21,  6,10,15,21,  6,10,15,21,  6,10,15,21
};

// ---------- core single-block compression ----------

__forceinline__ __device__ void md5_block(uint32_t state[4], const uint32_t M[16]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    #pragma unroll
    for (int i = 0; i < 64; ++i) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5u * (uint32_t)i + 1u) & 15u;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3u * (uint32_t)i + 5u) & 15u;
        } else {
            f = c ^ (b | (~d));
            g = (7u * (uint32_t)i) & 15u;
        }
        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + md5_rotl(a + f + QC_MD5_K[i] + M[g], QC_MD5_S[i]);
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// ---------- public API ----------

__device__ void md5_compute(const uint8_t* __restrict__ data, uint32_t len, uint8_t out[16]) {
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

    // Bloque temporal de 64 bytes vistos como 16 palabras de 32 bits LE.
    uint32_t M[16];

    // Procesa bloques completos del input (64 bytes cada uno).
    uint32_t offset = 0;
    while (offset + 64u <= len) {
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            uint32_t b0 = (uint32_t)data[offset + i * 4 + 0];
            uint32_t b1 = (uint32_t)data[offset + i * 4 + 1];
            uint32_t b2 = (uint32_t)data[offset + i * 4 + 2];
            uint32_t b3 = (uint32_t)data[offset + i * 4 + 3];
            M[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        md5_block(state, M);
        offset += 64u;
    }

    // Bloque final con padding: copia el resto, añade 0x80, ceros, y la
    // longitud total en bits LE en los últimos 8 bytes. Si no cabe la
    // longitud, hace falta un segundo bloque con solo la longitud.
    uint8_t buf[64];
    uint32_t rem = len - offset;
    #pragma unroll
    for (int i = 0; i < 64; ++i) buf[i] = 0;
    for (uint32_t i = 0; i < rem; ++i) {
        buf[i] = data[offset + i];
    }
    buf[rem] = 0x80;

    if (rem >= 56u) {
        // No cabe la longitud: este bloque solo lleva el sufijo del mensaje
        // + 0x80 + ceros, y luego un bloque adicional con la longitud.
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            uint32_t b0 = (uint32_t)buf[i * 4 + 0];
            uint32_t b1 = (uint32_t)buf[i * 4 + 1];
            uint32_t b2 = (uint32_t)buf[i * 4 + 2];
            uint32_t b3 = (uint32_t)buf[i * 4 + 3];
            M[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        md5_block(state, M);

        // Bloque solo de longitud.
        #pragma unroll
        for (int i = 0; i < 14; ++i) M[i] = 0;
        uint64_t bits = (uint64_t)len * 8ULL;
        M[14] = (uint32_t)(bits & 0xffffffffu);
        M[15] = (uint32_t)(bits >> 32);
        md5_block(state, M);
    } else {
        // Cabe la longitud en este último bloque.
        uint64_t bits = (uint64_t)len * 8ULL;
        buf[56] = (uint8_t)(bits >>  0);
        buf[57] = (uint8_t)(bits >>  8);
        buf[58] = (uint8_t)(bits >> 16);
        buf[59] = (uint8_t)(bits >> 24);
        buf[60] = (uint8_t)(bits >> 32);
        buf[61] = (uint8_t)(bits >> 40);
        buf[62] = (uint8_t)(bits >> 48);
        buf[63] = (uint8_t)(bits >> 56);
        #pragma unroll
        for (int i = 0; i < 16; ++i) {
            uint32_t b0 = (uint32_t)buf[i * 4 + 0];
            uint32_t b1 = (uint32_t)buf[i * 4 + 1];
            uint32_t b2 = (uint32_t)buf[i * 4 + 2];
            uint32_t b3 = (uint32_t)buf[i * 4 + 3];
            M[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        }
        md5_block(state, M);
    }

    // Output little-endian.
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        out[i * 4 + 0] = (uint8_t)(state[i] >>  0);
        out[i * 4 + 1] = (uint8_t)(state[i] >>  8);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
}

// Caso especializado: MD5 de 16 bytes (digest sobre digest). Cabe en un
// bloque, sin la rama de "bloque adicional para la longitud".
__forceinline__ __device__ void md5_compute_md5(const uint8_t in[16], uint8_t out[16]) {
    uint32_t state[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };
    uint32_t M[16] = { 0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0 };

    // 16 bytes de input → primeras 4 palabras LE.
    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        uint32_t b0 = (uint32_t)in[i * 4 + 0];
        uint32_t b1 = (uint32_t)in[i * 4 + 1];
        uint32_t b2 = (uint32_t)in[i * 4 + 2];
        uint32_t b3 = (uint32_t)in[i * 4 + 3];
        M[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
    // Padding 0x80 a partir del byte 16 → palabra M[4] = 0x00000080.
    M[4] = 0x00000080u;
    // Longitud en bits = 16 * 8 = 128 = 0x80, en M[14] LE.
    M[14] = 128u;
    M[15] = 0u;
    md5_block(state, M);

    #pragma unroll
    for (int i = 0; i < 4; ++i) {
        out[i * 4 + 0] = (uint8_t)(state[i] >>  0);
        out[i * 4 + 1] = (uint8_t)(state[i] >>  8);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 3] = (uint8_t)(state[i] >> 24);
    }
}
