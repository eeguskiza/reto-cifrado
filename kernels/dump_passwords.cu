// Kernel auxiliar exclusivamente para tests de paridad CPU↔GPU del
// generador combinatorio. No forma parte del barrido de producción.

#include "gen.cuh"

extern "C" __global__ void dump_passwords(
    uint64_t idx_base,
    uint64_t idx_count,
    uint8_t* __restrict__ out  // tamaño = idx_count * 14 bytes
) {
    uint64_t tid = (uint64_t)blockIdx.x * (uint64_t)blockDim.x + (uint64_t)threadIdx.x;
    if (tid >= idx_count) return;
    uint64_t idx = idx_base + tid;
    uint8_t pw[14];
    index_to_password(idx, pw);
    uint8_t* dst = out + tid * 14;
    #pragma unroll
    for (int i = 0; i < 14; ++i) {
        dst[i] = pw[i];
    }
}
