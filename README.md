# quattro-crack

Brute-force CUDA contra la construcción **cifraronline.com** confirmada
experimentalmente: AES-128-ECB + passraw (clave directa con null pad) +
NULL padding + MD5 integrity check del plaintext.

> Estado: **D-035 completado** (refactor a la construcción real).
>
> El barrido D-029 (8 h, 100 % del espacio, 0 hits) descartó la
> construcción asumida. El usuario hizo una prueba experimental: cifró
> un plaintext y password conocidos en **cifraronline.com** y comparó
> bit-exact contra el cipher local. Resultado: la construcción es
> totalmente distinta. Ver D-035 para la historia completa.
>
> **Construcción real verificada bit-exact contra `pycryptodome`:**
>
> ```
> key       = password.encode() + b'\x00' * (16 - len(password.encode()))
> message   = plaintext + MD5(plaintext).hexdigest().encode()
> padded    = message + b'\x00' * ((16 - len(message) % 16) % 16)
> ciphertext = AES-128-ECB.encrypt(padded, key)
> ```
>
> Kernel activo: **`brute_passraw_aes128_ecb` (D-035)**. ptxas:
> 64 regs/thread, 0 spill, 4624 B smem, `__launch_bounds__(128, 8)` →
> 1024 threads/SM (~67 % occupancy nominal). Sostiene **4,35 GH/s avg /
> 5,63 GH/s peak** sobre 30 s de benchmark — **2,9× más rápido que
> D-029** porque el KDF (MD5 + hexify) desaparece del hot path y AES-128
> es ~25 % más ligero que AES-256.
>
> El kernel legacy se conserva como `kernels/brute_legacy_aes256.cu`
> (NO compilado) por si hace falta volver a comparar. La historia
> completa de optimizaciones (D-029, D-030, D-034) sigue en
> `DECISIONS.md`.
>
> **105 tests verdes + 10 ignorados** (D-035 añadió 9 tests específicos
> y eliminó 5 de coop/d029 ya obsoletos). Clippy limpio con
> `-D warnings`. ETA del barrido único a 4,35 GH/s avg ≈ **3 h 48 min**.
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

## Construcción criptográfica (verificada bit-exact, D-035)

```
key       = password.encode() + b'\x00' * (16 - len(password.encode()))   # 16 B AES-128
message   = plaintext + MD5(plaintext).hexdigest().encode()               # plaintext + 32 B integrity
padded    = message + b'\x00' * ((16 - len(message) % 16) % 16)           # NULL padding (NO PKCS7)
ciphertext = AES-128-ECB.encrypt(padded, key)
```

ECB no usa IV. El fichero objetivo (`./data/cifrado.txt`) son **1616 B
de ciphertext puros** decodificados desde base64. Como el plaintext de
≈1584 B + 32 B de MD5 hex = 1616 B exactos, **no hay null padding** en
este caso particular. La biografía de Leonardo da Vinci en español
(≈1552 chars con tildes) cabe perfecta.

## Validación de hit (3 pasos, D-007 vigente bajo D-035)

Una clave es hit confirmado solo si:

1. primeros 16 B del PT = `Leonardo da Vinc` (kernel CUDA)
2. primeros 32 B del PT matchean **alguna** de:
   - `Leonardo da Vinci\n\nLeonardo da V` (LF, prueba experimental dio esto)
   - `Leonardo da Vinci\r\n\r\nLeonardo da` (CRLF, pizarra/Notepad)
3. tras strippear NULL padding del PT, los últimos 32 chars son
   `MD5(plaintext_clean).hexdigest()` (CPU)

Si pasa (1)+(2) pero falla (3) → bug crítico, runner aborta con
`Md5MismatchCritical` (probabilidad bajo AES real: ~2⁻¹²⁸).

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

| Throughput                     | ETA                   |
|--------------------------------|-----------------------|
| 4,35 GH/s avg (medido D-035)   | ~3 h 48 min           |
| 5,63 GH/s peak                 | ~2 h 56 min           |
| 1,48 GH/s avg (D-029, descart) | ~11,2 h               |

D-035 mejora **2,9× sobre D-029** (4,35 vs 1,49 GH/s) porque
elimina el KDF (MD5 + hexify) del hot path: la clave es directamente
`pw + null pad`. Más AES-128 vs AES-256 (10 rondas vs 14), ahorra
~25 % adicional. Sumado, ~3× speedup esperable y medido.

## Performance (post-D-035)

Throughput sobre RTX 5070 Ti, sm_120, batch 128 Mi, 30 s:

| Kernel                                | avg GH/s | peak GH/s | median GH/s | regs / spill / smem    |
|---------------------------------------|----------|-----------|-------------|------------------------|
| **D-035 passraw + AES-128** (activo)  | **4,35** | **5,63**  | 4,30        | 64 / 0 B / 4624 B      |
| D-029 md5hex + AES-256 (legacy)       | 1,49     | 1,82      | 1,42        | 80 / 84 B / 4624 B     |
| D-030 coop (descartado)               | 0,81     | 0,99      | 0,78        | 96 / 0 B / 12 304 B    |

El kernel D-035 cabe en `__launch_bounds__(128, 8)` (vs `(128, 6)` del
D-029) gracias a la menor presión de registros: rk[44] vs rk[60] +
ausencia de MD5 unrolled. Eso da 1024 threads/SM (vs 768 D-029) y cero
spill stores. La combinación occupancy + menor work-per-candidate
explica el 2,9× factor.

## Cómo se compone el path activo (D-035)

```
fichero base64 → 1616 B CT → CT[0..16] al kernel
                                  ↓
       idx ∈ [0, N) → password (gen.cuh, 14 B ASCII)
                          ↓
       key[16] = pw[0..14] || 0x00 0x00     (passraw, sin MD5 ni hexify)
                          ↓
                          AES-128 key schedule (rk[44])
                                                          ↓
                          AES-128 decrypt block (rk, CT[0..16])
                                                          ↓
                      compara 16 B vs "Leonardo da Vinc" (kernel)
                                                          ↓
                                                  match → atomic emit hit
                                                          ↓
                                  CPU: validate_hit
                                  - decrypt todo el ciphertext (1616 B)
                                  - prefijo-32 LF o CRLF
                                  - strip null pad → split last 32 = md5_hex
                                  - MD5(plaintext_clean) == embedded?
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
- [x] Fase 9 (D-030..D-033) — cooperative AES intra-warp **implementado y descartado**
      por throughput (45 % regresión); barrido de bugs adversariales
- [x] Fase 10 (D-034) — fix CRLF único en `KNOWN_PREFIX_32` + observabilidad de descartes
- [x] Fase 11 (D-035) — refactor a la construcción REAL cifraronline.com
      (passraw + AES-128 + null pad + MD5 verify), 105 tests verdes, 4,35 GH/s avg
- [ ] Esteganografía (post-barrido) — el plaintext descifrado contiene una frase
      oculta esteganográficamente; se procesa después de obtener el plaintext.

## Layout de la TUI

```
quattro-crack v1.0.0 — N = 59559806250000 — AES-128-ECB passraw + MD5 verify (D-035)
device: NVIDIA GeForce RTX 5070 Ti  ·  batch_size: 67108864  ·  config: passraw / aes-128-ecb / nullpad / md5verify

[Plan]   ████████████████████████████████  1/1 configurations  ·  D-035 single
[Config] passraw / aes-128-ecb / nullpad / md5verify  ·  AES-128
[Space]  ████████░░░░░░░░░░░░░░░░░░░░░░░░  25.4000%  1.51e13/5.96e13  ·  ETA 2h47m
[Speed]  ████████████████████████░░░░░░░░  4.35 GH/s  (peak 5.63, avg 4.30)
[GPU]    util 98%  ·  mem 4.1/16.0 GB  ·  temp 71°C  ·  power 218W
[State]  last flush 0.4s ago  ·  next_step 15123456789
                                                                       Hits found: 0
                                                                  Elapsed: 0h58m
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
- Compila el kernel activo `kernels/brute_passraw_aes128_ecb.cu` (D-035) +
  los kernels auxiliares de tests (`dump_passwords`, `md5_test`,
  `aes_test`, `force_emit_hits`, `dump_pt_block0` con AES-128). Los
  kernels legacy AES-256 (`brute_legacy_aes256.cu`,
  `brute_md5hex_aes256_ecb_coop.cu`, `dump_pt_block0_coop.cu`,
  `aes_coop.cuh`) quedan en árbol como archival pero NO se compilan.

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

### State legacy (pre-D-029 o pre-D-035)

Si tienes un `state/plan.toml` o `state/progress.toml` de antes del
refactor D-029 (con campos `entries`, `preset`, `per_config`,
`current_config`...) el binario aborta con mensaje claro pidiendo
`quattro-crack reset --yes`.

Si tienes un state de D-029..D-034 (`program_version = "0.2.0"`),
**la construcción cambió por completo en D-035**. El plan será
rechazado por `same_major()` (0.2.0 vs 1.0.0). Borra y arranca desde
cero:

```bash
quattro-crack reset --yes        # borra state/ legacy
quattro-crack run                # arranca plan único desde idx=0
```

### Mi barrido completó al 100 % sin hit, ¿qué hago?

Antes de relanzar a ciegas, **revisa los descartes
`PrefixMismatch32`** vía `quattro-crack status`:

```
prefix32 mismatch    1234 descartes (samples: idx=[100, 250, ...])
```

Esa línea aparece solo si `prefix32_mismatch_count > 0`. Significado:
el kernel reportó hits que coincidían en los 16 primeros bytes
(`Leonardo da Vinc`) pero la CPU descartó porque los siguientes 16 NO
matcheaban `KNOWN_PREFIX_32`. Bajo AES-256-ECB con plaintext real,
esto es ~2⁻¹²⁸ por puro azar — un descarte indica casi seguro un bug
en `KNOWN_PREFIX_32` o en la KDF/kernel/ciphertext. Ver D-034 para el
caso real de CRLF único que descartó la clave correcta durante un
barrido completo de 8 horas.

El log también lleva las entradas:

```
INFO PREFIX32_MISMATCH descartado por validación CPU (D-034)
     idx=... password=... plaintext_first_32_hex=...
```

Compara `plaintext_first_32_hex` con `KNOWN_PREFIX_32` byte a byte:
los 16 primeros B siempre coincidirán (es lo que filtra el kernel),
pero los 16 siguientes te dicen exactamente qué prefijo tiene el
plaintext real. Si tu constante hardcodeada está mal, ahí lo verás.

## Benchmark

```bash
# Throughput sostenido del kernel activo (D-035) durante 30 s.
quattro-crack benchmark --duration 30 --batch-size 134217728
```

Códigos de salida: 0 si ≥ 3 GH/s, 1 si entre 2–3 (warning), 2 si < 2.
En el hardware actual el avg típico de D-035 es 4,3–4,4 GH/s ⇒ exit
code 0. Para un piso operacional usa el test
`tests/optimized_kernel_parity.rs::test_throughput_meets_target` que
exige ≥ 2,0 GH/s.
