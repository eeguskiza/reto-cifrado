// brute_md5hex_aes256_ecb_coop.cu — variante COOPERATIVA del barrido (D-030).
//
// Configuración cableada (idéntica a la del kernel monolítico legacy):
//
//   key  = MD5(pw_utf8).hexdigest().encode("ascii")  // 32 B ASCII = AES-256
//   mode = AES-256-ECB                              // sin IV, sin XOR
//   pad  = PKCS7                                    // validado en CPU sobre el hit
//
// Modelo de paralelismo:
//   - block_dim = 128 threads = 4 warps por block
//   - cada warp = 32 lanes organizadas en 8 grupos de 4 (col 0..3)
//   - cada grupo de 4 hilos cooperativamente procesa UNA candidata
//   - lane%4 == 0  → leader (col 0): hace KDF + key schedule, escribe rk[60] a __shared__
//   - lane%4 == c  → follower (col c): lee su columna de rk (15 dwords) en regs
//   - los 4 hilos cooperan en el AES-256 decrypt mediante __shfl_sync(width=4)
//
// Memoria compartida por block:
//   - tablas Td0..Td3 (4 KB) + INV_SBOX + SBOX (512 B) + ct (16 B) = 4624 B
//   - rk[60] × 32 grupos = 1920 dwords = 7680 B
//   - Total: 12 304 B/block (Blackwell tiene >100 KB/SM disponibles).
//
// Por qué cooperativo aquí: el kernel legacy (`brute_md5hex_aes256_ecb.cu`)
// spillea 84 B por presión de rk[60] (60 dwords) sobre el cap de 80
// regs/thread de `__launch_bounds__(128,6)`. La variante cooperativa
// mueve rk[60] a __shared__, baja a ~50 regs/thread, y elimina el spill.
// La validación bit-exact frente a `reference::decrypt_ecb_raw` y al
// kernel legacy vive en `tests/coop_kernel_parity.rs` (1M idx, cero
// tolerancia).

#include <stdint.h>
#include "gen.cuh"
#include "md5.cuh"
#include "aes.cuh"
#include "aes_coop.cuh"

struct DeviceHit {
    uint64_t idx;
};

#ifndef QC_BLOCK_DIM_COOP
#define QC_BLOCK_DIM_COOP 128
#endif
#ifndef QC_BLOCKS_PER_SM_COOP
// PERF (D-030): probado (128,4..8) con ptxas. Cota a 5 da 96 regs/thread,
// 0 B de spill stores/loads, y 20 warps/SM (41.7% occupancy). Por encima
// de 5 hay spill creciente porque el path del leader (KDF + AES key
// schedule) tiene presión global de regs aunque solo lo ejecute 1 de 4
// threads del grupo. La calibración por throughput sostenido vive en
// `tests/coop_kernel_parity.rs::test_coop_kernel_throughput_30s`.
#define QC_BLOCKS_PER_SM_COOP 5
#endif

#define QC_GROUPS_PER_WARP    8
#define QC_GROUPS_PER_BLOCK   (QC_BLOCK_DIM_COOP / 4)  // 32
#define QC_WARPS_PER_BLOCK    (QC_BLOCK_DIM_COOP / 32) // 4

extern "C" __global__
__launch_bounds__(QC_BLOCK_DIM_COOP, QC_BLOCKS_PER_SM_COOP)
void brute_kernel_coop(
    uint64_t idx_base,
    uint64_t idx_count,
    const uint8_t* __restrict__ ct_block_0,    // 16 B
    DeviceHit* __restrict__ hits_out,
    uint32_t* __restrict__ hit_counter,
    uint32_t hits_capacity
) {
    // ---------- shared ----------
    __shared__ uint32_t s_td0[256];
    __shared__ uint32_t s_td1[256];
    __shared__ uint32_t s_td2[256];
    __shared__ uint32_t s_td3[256];
    __shared__ uint8_t  s_isbox[256];
    __shared__ uint8_t  s_sbox[256];
    __shared__ uint8_t  s_ct[16];
    __shared__ uint32_t s_rk[QC_GROUPS_PER_BLOCK][60];

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

    // ---------- topology ----------
    const int tid_in_block  = (int)threadIdx.x;
    const int lane          = tid_in_block & 31;
    const int warp_in_block = tid_in_block >> 5;
    const int group_in_warp = lane >> 2;
    const int col           = lane & 3;
    const int group_in_blk  = warp_in_block * QC_GROUPS_PER_WARP + group_in_warp;

    // Cada grupo procesa una candidata por iteración del stride loop.
    const uint64_t total_groups = (uint64_t)gridDim.x * (uint64_t)QC_GROUPS_PER_BLOCK;
    const uint64_t group_global = (uint64_t)blockIdx.x * (uint64_t)QC_GROUPS_PER_BLOCK
                                + (uint64_t)group_in_blk;

    // Pre-cargamos el target columnado: "Leonardo da Vinc" en LE.
    //   col 0: "Leon" = 0x6E6F654C   col 1: "ardo" = 0x6F647261
    //   col 2: " da " = 0x20616420   col 3: "Vinc" = 0x636E6956
    uint32_t target_col;
    switch (col) {
        case 0:  target_col = 0x6E6F654Cu; break;
        case 1:  target_col = 0x6F647261u; break;
        case 2:  target_col = 0x20616420u; break;
        default: target_col = 0x636E6956u; break;  // col 3
    }

    // Mi columna del ct (constante en todo el batch).
    const uint32_t my_ct_col = aes_get_u32_le(s_ct + col * 4);

    // ---------- hot loop ----------
    for (uint64_t pos = group_global; pos < idx_count; pos += total_groups) {
        const uint64_t idx = idx_base + pos;

        // ----- Fase 1: leader hace KDF + key schedule en shared. -----
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

            // Escribe directamente a s_rk[group_in_blk][0..59].
            uint32_t* my_rk = &s_rk[group_in_blk][0];
            aes256_set_key_with_tables(key, my_rk, s_td0, s_sbox);
        }

        // Followers esperan la rk del leader. Sincronización warp-wide
        // porque los 4 grupos del warp pueden estar desfasados.
        __syncwarp(0xffffffff);

        // ----- Fase 2: cada hilo carga su columna de rk a registros. -----
        uint32_t rk_col[15];
        #pragma unroll
        for (int r = 0; r < 15; ++r) {
            rk_col[r] = s_rk[group_in_blk][r * 4 + col];
        }

        // ----- Fase 3: cooperative AES-256 decrypt. -----
        const uint32_t state = aes256_decrypt_block_coop(
            my_ct_col, rk_col, col,
            s_td0, s_td1, s_td2, s_td3, s_isbox);

        // ----- Fase 4: comparación de prefijo + emisión de hit. -----
        const uint32_t my_diff = state ^ target_col;

        // ballot_sync devuelve un mask de 32 bits con el predicado de cada lane.
        // Los 4 bits relevantes de mi grupo viven en posiciones [g*4, g*4+3]
        // dentro del warp (g = group_in_warp).
        const unsigned ballot = __ballot_sync(0xffffffffu, my_diff != 0u);
        const unsigned my_grp = (ballot >> (group_in_warp * 4)) & 0xfu;

        if (col == 0 && my_grp == 0u) {
            uint32_t slot = atomicAdd(hit_counter, 1u);
            if (slot < hits_capacity) {
                hits_out[slot].idx = idx;
            }
        }
    }
}
