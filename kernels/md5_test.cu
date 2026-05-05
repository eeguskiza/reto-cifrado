// kernels/md5_test.cu — kernel auxiliar para validar md5_compute device
// contra los vectores RFC 1321 desde Rust.

#include "md5.cuh"

extern "C" __global__ void md5_test(
    const uint8_t* __restrict__ data,    // n_inputs * stride bytes
    const uint32_t* __restrict__ lens,   // n_inputs
    uint32_t stride,                      // bytes por slot de entrada
    uint32_t n_inputs,
    uint8_t* __restrict__ out             // n_inputs * 16 bytes
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_inputs) return;
    md5_compute(data + (uint64_t)tid * stride, lens[tid], out + (uint64_t)tid * 16);
}

extern "C" __global__ void md5_md5_test(
    const uint8_t* __restrict__ digests, // n * 16 bytes
    uint32_t n,
    uint8_t* __restrict__ out             // n * 16 bytes
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n) return;
    uint8_t local[16];
    #pragma unroll
    for (int i = 0; i < 16; ++i) local[i] = digests[tid * 16 + i];
    uint8_t out_local[16];
    md5_compute_md5(local, out_local);
    #pragma unroll
    for (int i = 0; i < 16; ++i) out[tid * 16 + i] = out_local[i];
}
