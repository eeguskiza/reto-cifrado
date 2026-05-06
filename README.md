# quattro-crack

Brute-force CUDA contra **AES-256-ECB + PKCS7** con `md5hex_full` como
única KDF y estructura de password conocida.

> Estado: **Fase 8 (D-029) completada**. El autor del reto confirmó
> oficialmente la construcción criptográfica final:
>
> - **Modo:** AES-256-ECB con padding PKCS7
> - **KDF:** `key = MD5(password.encode("utf-8")).hexdigest().encode("ascii")`
>   → 32 B ASCII
> - **IV:** ninguno (ECB)
>
> Tras el refactor el barrido tiene **una única configuración**, un
> único PTX (`brute_md5hex_aes256_ecb.cu`) y la CLI ya no expone
> presets ni KDFs alternativas. Las 13 KDFs anteriores y el path CBC
> sobreviven como código auxiliar de tests (`kdf::legacy::*`,
> `reference::{decrypt,encrypt}_cbc_*` con `#[doc(hidden)]`). El
> kernel monolítico sostiene **1,48 GH/s avg / 1,82 GH/s peak** sobre
> 30 s de benchmark (vs 1,76 GH/s avg de md5hex_full bajo el kernel
> multi-KDF anterior — ver D-029).
>
> 81 tests verdes + 10 ignorados (diagnóstico opt-in). Clippy limpio
> con `-D warnings`. ETA del barrido único a 1,48 GH/s avg ≈ **11,2 h**.
>
> Optimizaciones D-025 (batch 64 Mi default), D-026 (flush agrupado
> cada 8 batches) y D-027 (NVML shim WSL2) heredadas y vigentes.

## Estructura del password objetivo

14 caracteres exactos con la forma `.LLLLLLLL1NNN.`:

- `.` literal
- 8 letras ASCII `[a-zA-Z]` con **exactamente 4 vocales** (`aeiou`) +
  **4 consonantes** (las 21 ASCII restantes)
- **Exactamente 1 mayúscula** entre las 8 letras, y **no** en la primera
  posición del bloque
- `1` literal
- 3 dígitos `NNN`
- `.` literal

Cardinalidad del espacio:

```
70 × 625 × 194 481 × 7 × 1000 = 59 559 806 250 000  ≈ 5.96 × 10¹³
```

## Construcción criptográfica (confirmada por el autor — D-029)

```
key  = MD5(password.encode("utf-8")).hexdigest().encode("ascii")  # 32 B AES-256
mode = AES-256-ECB
pad  = PKCS7
```

ECB no usa IV. El fichero objetivo (`./data/cifrado.txt`) son **1616 B
de ciphertext puros**, decodificados desde base64, divididos en
**101 bloques AES de 16 B**.

## Validación de hit (3 pasos, D-007 vigente)

Una clave es hit confirmado solo si:

1. primeros 16 B del PT = `Leonardo da Vinc` (kernel)
2. primeros 32 B del PT = `Leonardo da Vinci\r\nLeonardo da V` (CPU)
3. padding PKCS7 del último bloque válido (CPU)

Si pasa (1)+(2) pero falla (3) → bug crítico, runner aborta.

## Build

```bash
cargo build --release
cargo test --release
```

## Uso

```bash
# Inspeccionar fichero objetivo (sin IV, ECB)
quattro-crack inspect ./data/cifrado.txt

# Ver el plan único
quattro-crack plan

# Persistir plan en state/plan.toml
quattro-crack plan --save

# Ver estado actual (plan + progreso)
quattro-crack status

# Lanzar el barrido (plan único, sin presets)
quattro-crack run

# Reanudar tras pausa
quattro-crack run --resume

# Borrar state (incluido state legacy pre-D-029)
quattro-crack reset --yes
```

## Tiempos estimados

ETA = N / throughput (espacio único, sin presets).

| Throughput                     | ETA                  |
|--------------------------------|----------------------|
| 1,48 GH/s avg (medido D-029)   | ~11,2 h ≈ 0,47 días  |
| 1,82 GH/s peak                 | ~9,1 h               |
| 1,26 GH/s runner real (hot)    | ~13,1 h              |

vs baseline pre-D-029: el plan exhaustive de 42 configs tardaba
~37 h ≈ 1,5 días, así que el refactor da un **speedup × 3** efectivo
(no por kernel más rápido, sino por 1 paso del espacio en lugar de 42).

## Performance (post-D-029)

Throughput del kernel único `brute_md5hex_aes256_ecb` (RTX 5070 Ti,
sm_120, batch 128 Mi, 30 s sostenido):

| Métrica  | GH/s     |
|----------|----------|
| avg      | **1,48** |
| peak     | 1,82     |
| median   | 1,42     |

**Comparativa con el kernel multi-KDF anterior**:

| Kernel                                  | KDF/path        | GH/s avg |
|-----------------------------------------|-----------------|----------|
| Multi-KDF Fase 6 (md5_utf8 / AES-128 / CBC) | más rápido  | 1,87     |
| Multi-KDF Fase 6 (md5hex_full / AES-256 / CBC) | comparable | 1,76     |
| **Único D-029 (md5hex_full / AES-256 / ECB)** | **activo** | **1,48 / 1,82 peak** |

AES-256 es ~30 % más lento que AES-128 (14 rondas vs 10, rk de 60 vs
44). La eliminación del dispatch IV/KDF aporta ~5 % vs el path
md5hex+AES-256 multi-KDF anterior; el resto es coste estructural de
AES-256 que no cambia. Ver D-029 para el análisis completo.

## Cómo se compone el path activo

```
fichero base64 → 1616 B CT → CT[0..16] al kernel
                                  ↓
       idx ∈ [0, N) → password (gen.cuh, 14 B ASCII)
                          ↓
          MD5(pw) → 16 B raw → ASCII hex lowercase → 32 B key
                                                          ↓
                                  AES-256 key schedule (rk[60])
                                                          ↓
                                  AES-256 decrypt block (rk, CT[0..16])
                                                          ↓
                              compara 16 B vs "Leonardo da Vinc" (kernel)
                                                          ↓
                                                  match → atomic emit hit
                                                          ↓
                                  CPU: validate_hit (prefijo-32 + PKCS7)
                                                          ↓
                                                       Confirmed → exit
```

## Roadmap

- [x] Fase 0 — esqueleto + loader + `inspect`
- [x] Fase 1 — generador combinatorio CPU
- [x] Fase 2 — KDFs + descifrado CPU + plan + estado atómico + CLI ampliada
- [x] Fase 3 — kernels CUDA (gen, MD5, AES-128/192/256, brute parametrizado)
- [x] Fase 4 — runner + checkpointing + reanudación + signal handling
- [x] Fase 5 — TUI en vivo + tracing-appender (logs/) + auto-TTY
- [x] Fase 6 — optimización kernel (launch_bounds + N/thread + Td0 invmix), 1.10 → 2.37 GH/s
- [x] Fase 7 — flush agrupado + batch 64 Mi default + fix NVML WSL2: runner 0,91 → 1,88 GH/s
- [x] Fase 8 (D-029) — refactor a única config (AES-256-ECB + md5hex_full), 81 tests verdes
- [ ] Fase 9 (deuda) — cooperative AES intra-warp para empujar AES-256 hacia 2-3 GH/s

## Layout de la TUI

```
quattro-crack v0.2.0 — N = 59559806250000 — AES-256-ECB (PKCS7), md5hex_full
device: NVIDIA GeForce RTX 5070 Ti  ·  batch_size: 67108864  ·  config: md5hex_full / aes-256-ecb / pkcs7

[Plan]   ████████████████████████████████  1/1 configurations  ·  D-029 single
[Config] md5hex_full / aes-256-ecb / pkcs7  ·  AES-256
[Space]  ████████░░░░░░░░░░░░░░░░░░░░░░░░  25.4000%  1.51e13/5.96e13  ·  ETA 8h22m
[Speed]  ████████████████████████░░░░░░░░  1.48 GH/s  (peak 1.82, avg 1.45)
[GPU]    util 98%  ·  mem 4.1/16.0 GB  ·  temp 71°C  ·  power 218W
[State]  last flush 0.4s ago  ·  next_step 15123456789
                                                                       Hits found: 0
                                                                  Elapsed: 2h47m
                                                          Press Ctrl+C to pause and save state safely.
```

## Build CUDA

Prerequisitos:
- CUDA Toolkit ≥ 12.8 (recomendado 13.0). Detectado: `nvcc --version`.
- GPU NVIDIA con compute capability ≥ 8.9 (Ada) — nativo a 12.0 (Blackwell).
- Driver compatible (en WSL2: el driver Windows expone CUDA al guest).

`build.rs` automáticamente:
- Detecta `nvcc` (PATH, `NVCC`, `CUDA_HOME`, rutas estándar).
- Comprueba si soporta `-arch=sm_120` (Blackwell). Si no, cae a `sm_89` (Ada).
- Compila **un único** `kernels/brute_md5hex_aes256_ecb.cu` (D-029) +
  los kernels auxiliares de tests (`dump_passwords`, `md5_test`,
  `aes_test`, `force_emit_hits`, `dump_pt_block0`).

## Troubleshooting WSL2

### CUDA Toolkit (nvcc)

A partir de Fase 3 hace falta `nvcc` (CUDA Toolkit) en WSL, **no solo el
driver de Windows**:

```bash
cd /tmp
wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install -y cuda-toolkit-13-0
echo 'export PATH=/usr/local/cuda-13.0/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-13.0/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

**No instales** `cuda-drivers-*` ni `nvidia-driver-*` en WSL.

### NVML — línea `[GPU] metrics unavailable` (D-027)

WSL2 expone `libnvidia-ml.so.1` en `/usr/lib/wsl/lib/` pero no crea el
symlink `libnvidia-ml.so`. Fix:

```bash
# Con sudo (recomendado, una vez por máquina):
sudo ln -s /usr/lib/wsl/lib/libnvidia-ml.so.1 /usr/lib/wsl/lib/libnvidia-ml.so
sudo ldconfig

# Sin sudo (per-usuario):
mkdir -p ~/lib-nvml-shim
ln -sf /usr/lib/wsl/lib/libnvidia-ml.so.1 ~/lib-nvml-shim/libnvidia-ml.so
echo 'export LD_LIBRARY_PATH=$HOME/lib-nvml-shim:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

El barrido funciona perfectamente sin NVML; solo se pierden las
métricas decorativas de la TUI.

### State legacy pre-D-029

Si tienes un `state/plan.toml` o `state/progress.toml` de antes del
refactor D-029 (con campos `entries`, `preset`, `per_config`,
`current_config`...) el binario aborta con mensaje claro:

```
state/plan.toml pertenece a una versión incompatible (pre-D-029,
formato multi-config). Lánzalo con `quattro-crack reset --yes` para
empezar de cero, o renombra/copia el fichero si quieres conservarlo.
```

Para reanudar el barrido bajo el nuevo formato:

```bash
quattro-crack reset --yes        # borra state/ legacy
quattro-crack run                # arranca plan único desde idx=0
```

## Benchmark

```bash
# Throughput sostenido del kernel único durante 30 s.
quattro-crack benchmark --duration 30 --batch-size 134217728
```

Códigos de salida: 0 si ≥ 3 GH/s, 1 si entre 2–3 (warning), 2 si < 2.
En el hardware actual el avg típico es 1,4–1,5 GH/s ⇒ exit code 2,
esperado tras D-029 (AES-256 es estructuralmente ~30 % más lento que
AES-128). Para un piso operacional usa el test
`tests/optimized_kernel_parity.rs::test_throughput_meets_target` que
exige ≥ 1,0 GH/s.
