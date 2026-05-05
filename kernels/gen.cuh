// gen.cuh — generador combinatorio device, espejo bit-a-bit del CPU.
//
// Mapea idx ∈ [0, N) → password de 14 bytes con la estructura
//
//   . L L L L L L L L 1 N N N .
//
// Decomposición en 5 campos de mayor a menor peso (ver DECISIONS.md D-002):
//
//   year (1000) → disp (70) → upper (7) → cons (21^4) → vowel (5^4)
//
// La tabla DISPOSITIONS contiene las 70 combinaciones C(8,4) en orden
// lexicográfico estándar; debe coincidir byte a byte con la const-fn
// `combinatorics::build_dispositions()` en Rust. La paridad CPU↔GPU se
// valida en tests/cpu_gpu_parity.rs sobre el primer millón de índices,
// con cero tolerancia.

#pragma once

#include <stdint.h>

// 70 disposiciones de 4 elementos tomados de {0..7} en orden lexicográfico.
// CADA UNA dice qué 4 posiciones del bloque de 8 letras llevan vocal.
__device__ __constant__ uint8_t QC_DISPOSITIONS[70][4] = {
    {0,1,2,3}, {0,1,2,4}, {0,1,2,5}, {0,1,2,6}, {0,1,2,7},
    {0,1,3,4}, {0,1,3,5}, {0,1,3,6}, {0,1,3,7}, {0,1,4,5},
    {0,1,4,6}, {0,1,4,7}, {0,1,5,6}, {0,1,5,7}, {0,1,6,7},
    {0,2,3,4}, {0,2,3,5}, {0,2,3,6}, {0,2,3,7}, {0,2,4,5},
    {0,2,4,6}, {0,2,4,7}, {0,2,5,6}, {0,2,5,7}, {0,2,6,7},
    {0,3,4,5}, {0,3,4,6}, {0,3,4,7}, {0,3,5,6}, {0,3,5,7},
    {0,3,6,7}, {0,4,5,6}, {0,4,5,7}, {0,4,6,7}, {0,5,6,7},
    {1,2,3,4}, {1,2,3,5}, {1,2,3,6}, {1,2,3,7}, {1,2,4,5},
    {1,2,4,6}, {1,2,4,7}, {1,2,5,6}, {1,2,5,7}, {1,2,6,7},
    {1,3,4,5}, {1,3,4,6}, {1,3,4,7}, {1,3,5,6}, {1,3,5,7},
    {1,3,6,7}, {1,4,5,6}, {1,4,5,7}, {1,4,6,7}, {1,5,6,7},
    {2,3,4,5}, {2,3,4,6}, {2,3,4,7}, {2,3,5,6}, {2,3,5,7},
    {2,3,6,7}, {2,4,5,6}, {2,4,5,7}, {2,4,6,7}, {2,5,6,7},
    {3,4,5,6}, {3,4,5,7}, {3,4,6,7}, {3,5,6,7}, {4,5,6,7}
};

__device__ __constant__ uint8_t QC_VOWELS[5]      = {'a','e','i','o','u'};
__device__ __constant__ uint8_t QC_CONSONANTS[21] = {
    'b','c','d','f','g','h','j','k','l','m','n','p','q','r','s','t','v','w','x','y','z'
};

// Multiplicadores acumulados por campo (mismos que en Rust).
#define QC_M_YEAR   59559806250ULL
#define QC_M_DISP     850854375ULL
#define QC_M_UPPER    121550625ULL
#define QC_M_CONS            625ULL

// 5^3, 5^2, 5
#define QC_V_125 125u
#define QC_V_25   25u
#define QC_V_5     5u

// 21^3, 21^2, 21
#define QC_C_9261 9261u
#define QC_C_441   441u
#define QC_C_21     21u

__forceinline__ __device__ void index_to_password(uint64_t idx, uint8_t pw[14]) {
    // Descomponer idx en (year, disp, upper, cons, vowel) — mismas divisiones
    // que la versión CPU.
    uint64_t year  = idx / QC_M_YEAR;
    uint64_t r1    = idx - year * QC_M_YEAR;
    uint32_t disp  = (uint32_t)(r1 / QC_M_DISP);
    uint64_t r2    = r1  - (uint64_t)disp  * QC_M_DISP;
    uint32_t upper = (uint32_t)(r2 / QC_M_UPPER);
    uint64_t r3    = r2  - (uint64_t)upper * QC_M_UPPER;
    uint32_t cons  = (uint32_t)(r3 / QC_M_CONS);
    uint32_t vowel = (uint32_t)(r3  - (uint64_t)cons  * QC_M_CONS);

    // Dígitos MSB-first: vocales en base 5, consonantes en base 21.
    uint8_t vd0 = (uint8_t)(vowel / QC_V_125);
    uint8_t vd1 = (uint8_t)((vowel / QC_V_25) % 5);
    uint8_t vd2 = (uint8_t)((vowel / QC_V_5)  % 5);
    uint8_t vd3 = (uint8_t)( vowel             % 5);

    uint8_t cd0 = (uint8_t)(cons  / QC_C_9261);
    uint8_t cd1 = (uint8_t)((cons / QC_C_441) % 21);
    uint8_t cd2 = (uint8_t)((cons / QC_C_21)  % 21);
    uint8_t cd3 = (uint8_t)( cons             % 21);

    uint8_t letters[8];

    // Coloca las vocales en sus 4 posiciones según la disposición.
    uint8_t vp0 = QC_DISPOSITIONS[disp][0];
    uint8_t vp1 = QC_DISPOSITIONS[disp][1];
    uint8_t vp2 = QC_DISPOSITIONS[disp][2];
    uint8_t vp3 = QC_DISPOSITIONS[disp][3];
    letters[vp0] = QC_VOWELS[vd0];
    letters[vp1] = QC_VOWELS[vd1];
    letters[vp2] = QC_VOWELS[vd2];
    letters[vp3] = QC_VOWELS[vd3];

    // Posiciones de consonantes = complemento.
    uint8_t mask = (uint8_t)(((uint8_t)1 << vp0) | ((uint8_t)1 << vp1)
                           | ((uint8_t)1 << vp2) | ((uint8_t)1 << vp3));
    uint8_t cd[4] = { cd0, cd1, cd2, cd3 };
    uint8_t k = 0;
    #pragma unroll
    for (uint8_t p = 0; p < 8; ++p) {
        if ((mask & ((uint8_t)1 << p)) == 0) {
            letters[p] = QC_CONSONANTS[cd[k]];
            ++k;
        }
    }

    // Mayúscula en letters[upper + 1] (posiciones 1..7 del bloque, 0-indexado).
    uint8_t upos = (uint8_t)(upper + 1);
    if (letters[upos] >= 'a' && letters[upos] <= 'z') {
        letters[upos] = (uint8_t)(letters[upos] - 32);
    }

    // Frame del password completo.
    pw[0] = '.';
    pw[1] = letters[0]; pw[2] = letters[1]; pw[3] = letters[2]; pw[4] = letters[3];
    pw[5] = letters[4]; pw[6] = letters[5]; pw[7] = letters[6]; pw[8] = letters[7];
    pw[9] = '1';
    uint32_t y = (uint32_t)year;
    pw[10] = (uint8_t)('0' + (y / 100u) % 10u);
    pw[11] = (uint8_t)('0' + (y /  10u) % 10u);
    pw[12] = (uint8_t)('0' +  y          % 10u);
    pw[13] = '.';
}
