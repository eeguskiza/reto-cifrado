// kernels/aes_test.cu — kernels auxiliares para validar aes.cuh
// contra los vectores NIST FIPS-197 desde Rust.

#include "aes.cuh"

// AES-128 decrypt: para cada slot, lee key[16] + ct[16] y escribe pt[16].
extern "C" __global__ void aes128_decrypt_test(
    const uint8_t* __restrict__ keys,    // n * 16 bytes
    const uint8_t* __restrict__ cts,     // n * 16 bytes
    uint32_t n,
    uint8_t* __restrict__ pts            // n * 16 bytes
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;

    uint8_t key_local[16], ct_local[16], pt_local[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        key_local[i] = keys[tid * 16 + i];
        ct_local[i]  = cts[tid * 16 + i];
    }

    uint32_t rk[44];
    aes128_set_key(key_local, rk);
    aes128_decrypt_block(rk, ct_local, pt_local);

    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        pts[tid * 16 + i] = pt_local[i];
    }
}

extern "C" __global__ void aes192_decrypt_test(
    const uint8_t* __restrict__ keys,    // n * 24 bytes
    const uint8_t* __restrict__ cts,     // n * 16 bytes
    uint32_t n,
    uint8_t* __restrict__ pts            // n * 16 bytes
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;

    uint8_t key_local[24], ct_local[16], pt_local[16];
    #pragma unroll
    for (int i = 0; i < 24; ++i) key_local[i] = keys[tid * 24 + i];
    #pragma unroll
    for (int i = 0; i < 16; ++i) ct_local[i]  = cts[tid * 16 + i];

    uint32_t rk[52];
    aes192_set_key(key_local, rk);
    aes192_decrypt_block(rk, ct_local, pt_local);

    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        pts[tid * 16 + i] = pt_local[i];
    }
}

extern "C" __global__ void aes256_decrypt_test(
    const uint8_t* __restrict__ keys,    // n * 32 bytes
    const uint8_t* __restrict__ cts,     // n * 16 bytes
    uint32_t n,
    uint8_t* __restrict__ pts            // n * 16 bytes
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;

    uint8_t key_local[32], ct_local[16], pt_local[16];
    #pragma unroll
    for (int i = 0; i < 32; ++i) key_local[i] = keys[tid * 32 + i];
    #pragma unroll
    for (int i = 0; i < 16; ++i) ct_local[i]  = cts[tid * 16 + i];

    uint32_t rk[60];
    aes256_set_key(key_local, rk);
    aes256_decrypt_block(rk, ct_local, pt_local);

    #pragma unroll
    for (int i = 0; i < 16; ++i) {
        pts[tid * 16 + i] = pt_local[i];
    }
}
