// kernels/force_emit_hits.cu — kernel auxiliar para tests del buffer de hits.
//
// Cada thread con tid < n_target emite un hit sintético. Sirve para
// validar:
//   - el contador atómico,
//   - la escritura paralela a `hits_out`,
//   - la detección de overflow cuando count > capacity.
//
// El path real (brute_kernel) es estructuralmente incapaz de generar
// más de un puñado de hits en un launch (la probabilidad de coincidir
// con el prefijo es ~2⁻¹²⁸ por candidata), así que este kernel
// reemplaza ese flujo concreto por un equivalente determinista.

#include <stdint.h>

struct DeviceHit {
    uint64_t idx;
    uint32_t kdf_id;
    uint32_t iv_id;
};

extern "C" __global__ void force_emit_hits(
    uint32_t n_target,
    DeviceHit* __restrict__ hits_out,
    uint32_t* __restrict__ hit_counter,
    uint32_t hits_capacity
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= n_target) return;

    uint32_t slot = atomicAdd(hit_counter, 1u);
    if (slot < hits_capacity) {
        hits_out[slot].idx    = (uint64_t)tid + 1000000ULL;
        hits_out[slot].kdf_id = 0xdeadbeefu;
        hits_out[slot].iv_id  = tid; // útil para verificar que cada slot
                                     // viene de un thread distinto
    }
}
