# quattro-crack

Brute-force CUDA contra la construcción de **cifraronline.com** (AES-128-ECB
+ passraw + null padding + MD5 verify), con barrido determinista del espacio
combinatorio `.LLLLLLLL1NNN.` (≈ 5,96 × 10¹³ candidatas).

> **Reto resuelto** ✅ — clave: `.viTrubio1490.`
> (Vitruvio + 1490, año del *Hombre de Vitruvio*).
> Pico medido en producción: **6 GH/s**. Avg sostenido: ~4,3 GH/s.
> Barrido completo cabe en **~3 h 50 min**.

---

## Construcción criptográfica (D-035)

```
key       = password.encode() + b'\x00' * (16 - len(password.encode()))
message   = plaintext + MD5(plaintext).hexdigest().encode()
padded    = message + b'\x00' * ((16 - len(message) % 16) % 16)
ciphertext = AES-128-ECB.encrypt(padded, key)
```

- **Clave**: directa, sin KDF. 14 B de password + 2 ceros.
- **Padding**: NULL (no PKCS7). En el reto el plaintext mide 1584 B y el
  MD5 hex añade 32 B → 1616 B exactos, sin padding.
- **Integrity**: los últimos 32 chars del plaintext son `MD5(plaintext_clean).hexdigest()`.
- **Salto de línea**: el barrido valida LF (`\n`) y CRLF (`\r\n`) en paralelo.

Ver `DECISIONS.md` D-035 para la historia completa (cómo se descubrió la
construcción real tras 8 h de barrido D-029 fallido).

## Estructura del password

14 caracteres con la forma `.LLLLLLLL1NNN.`:

- 8 letras ASCII con **4 vocales** + **4 consonantes** + **1 mayúscula no
  en pos 1 del bloque**.
- 3 dígitos `NNN` (000..999, año).

Cardinalidad: `70 × 625 × 194 481 × 7 × 1000 = 59 559 806 250 000`.

---

## Requisitos

- Linux o WSL2 con **GPU NVIDIA** visible (`nvidia-smi`).
- **CUDA Toolkit ≥ 12.8** con `nvcc` en PATH (recomendado 13.0).
- **Rust** ≥ 1.75 (para `cargo build`).
- Compute capability ≥ 8.9 (Ada). Nativo a 12.0 (Blackwell, RTX 50xx).

```bash
nvcc --version          # debe imprimir versión ≥ 12.8
rustc --version         # ≥ 1.75
nvidia-smi              # GPU visible
```

## Build

```bash
cargo build --release
```

`build.rs` detecta `nvcc` y compila el kernel a PTX para `sm_120` (con
fallback a `sm_89`). El binario va a `target/release/quattro-crack`.

## Setup WSL2 (una vez por máquina)

```bash
# 1) CUDA Toolkit (NO instales drivers — los provee Windows)
wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update && sudo apt-get install -y cuda-toolkit-13-0
echo 'export PATH=/usr/local/cuda-13.0/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-13.0/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# 2) Symlink NVML para la TUI (opcional, sin esto solo se pierde la línea [GPU])
mkdir -p ~/lib-nvml-shim
ln -sf /usr/lib/wsl/lib/libnvidia-ml.so.1 ~/lib-nvml-shim/libnvidia-ml.so
echo 'export LD_LIBRARY_PATH=$HOME/lib-nvml-shim:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

---

## Uso

```bash
# Inspeccionar el fichero objetivo (sin lanzar barrido).
quattro-crack inspect ./data/cifrado.txt

# Crear/persistir el plan único.
quattro-crack plan --save

# Lanzar el barrido (TUI auto si hay TTY).
quattro-crack run

# Reanudar tras pausa (Ctrl+C anterior).
quattro-crack run --resume

# Ver estado actual.
quattro-crack status

# Borrar todo el estado.
quattro-crack reset --yes

# Benchmark del kernel (30 s por defecto).
quattro-crack benchmark --duration 30 --batch-size 134217728
```

### Lanzar como tarea de fondo (recomendado para barrido nocturno)

```bash
LD_LIBRARY_PATH="$HOME/lib-nvml-shim:$LD_LIBRARY_PATH" \
  tmux new -s qc -d './target/release/quattro-crack run'

# Adjuntar para mirar la TUI:
tmux attach -t qc

# Pausar limpio (Ctrl+C dentro del tmux):
#   - El runner termina el batch en curso, persiste state, sale.
#   - `tmux attach` y luego `Ctrl+C` o `tmux kill-session -t qc` con SIGINT.
```

### Pausar/reanudar de forma segura

- **Primer Ctrl+C**: termina el batch en curso, escribe `state/progress.toml`
  atómicamente, sale con código 0. Se puede reanudar con `--resume`.
- **Segundo Ctrl+C** durante el shutdown: aborto inmediato (código 130).
- En el peor caso (SIGKILL/cuelgue) se pierde un único batch — los flushes
  son atómicos (`tmp → fsync → rename`) y se hace flush forzado en cada
  evento crítico (hit, error, signal).

---

## Output esperado

Cuando el barrido encuentra la clave imprime en stdout:

```
HIT  pw='.viTrubio1490.' idx=29097...   elapsed=...s
```

…y persiste el plaintext completo en `state/progress.toml` campo `hits`.

Si el barrido completa sin hit:

```
DONE  plan completado SIN hit (13702.12s)
```

Revisa entonces `state/progress.toml` campo `prefix32_mismatch_count` y
los logs `logs/run-*.log`. Cualquier descarte > 0 indica que alguna
hipótesis (LF/CRLF, prefijo, construcción) es falsa — revisa
`info!` con `plaintext_first_32_hex` para diagnosticar.

---

## Performance (RTX 5070 Ti, sm_120, batch 128 Mi)

| Métrica          | Valor               |
|------------------|---------------------|
| **Pico medido**  | **~6 GH/s**         |
| Avg 30 s bench   | 4,35 GH/s           |
| Median 30 s      | 4,30 GH/s           |
| ETA barrido N    | ~3 h 50 min @ 4,3   |
| ETA barrido N    | ~2 h 45 min @ 6,0   |

El kernel activo (`brute_passraw_aes128_ecb.cu`) usa
`__launch_bounds__(128, 8)`: 64 regs/thread, **0 spill**, 4624 B smem,
1024 threads/SM (~67 % occupancy nominal).

Comparativa con kernels descartados:

| Kernel                                    | avg GH/s | nota                          |
|-------------------------------------------|----------|-------------------------------|
| **D-035 passraw + AES-128** (activo)      | **4,35** | sin MD5 ni hexify en hot path |
| D-029 md5hex + AES-256 (legacy)           | 1,49     | KDF dominaba ~60% del coste   |
| D-030 cooperative AES intra-warp          | 0,81     | descartado por throughput     |

---

## Estructura del repo

```
src/
  combinatorics.rs   generador idx ↔ password (bijección)
  reference.rs       AES-128-ECB CPU + validate_hit + helpers cifraronline
  cuda.rs            bindings cudarc, KernelBundle, gpu_dump_pt_block0
  runner.rs          orquestación del barrido + checkpointing
  state.rs           persistencia atómica (plan.toml, progress.toml)
  plan.rs            descripción de la única configuración
  tui.rs             renderer en vivo (5 Hz) desacoplado por canal
  gpu_metrics.rs     muestreo NVML (util/mem/temp/power)
  signal.rs          handlers SIGINT/SIGTERM con shutdown limpio
  ciphertext.rs      loader del fichero base64 → 1616 B
  kdf.rs             passraw + catálogo legacy de 14 KDFs (tests)
  main.rs            CLI (clap) — inspect / plan / run / status / reset / benchmark

kernels/
  brute_passraw_aes128_ecb.cu    kernel ACTIVO D-035
  brute_legacy_aes256.cu         kernel D-029 archivado (no compilado)
  aes.cuh / aes_tables.cuh       primitivas AES-128/192/256 + Td-tables
  md5.cuh                        MD5 device (RFC 1321)
  gen.cuh                        generador device (espejo de combinatorics.rs)

tests/
  d035_cifraronline_construction.rs   vector experimental bit-exact + 9 tests
  optimized_kernel_parity.rs          1M idx CPU↔GPU bit-exact + throughput
  block4_adversarial.rs               boundaries + batch sizes + false positives
  resume.rs / runner_throughput.rs    pausa/reanuda + flush agrupado
  aes_fips197.rs / md5_rfc1321.rs     primitivas vs vectores estándar
  ...
```

---

## Tests

```bash
cargo test --release             # 105 tests verdes + 10 ignored (diagnóstico opt-in)
cargo clippy --release --all-targets -- -D warnings   # lint clean
```

El test ancla es
`tests/d035_cifraronline_construction.rs::test_experimental_vector_bit_exact`:
cifra el vector experimental conocido y compara byte-a-byte con el resultado
de cifraronline.com. Si falla, **toda la construcción está mal**.

---

## Troubleshooting

### `[GPU] metrics unavailable`
Falta el symlink NVML en WSL2. Ver "Setup WSL2" arriba.
El barrido funciona intacto sin esto; solo se pierde la línea decorativa.

### `LegacyFormat` al reanudar
Tienes un `state/` de versión vieja (pre-D-035). Solución:
```bash
quattro-crack reset --yes
quattro-crack run
```

### El fichero objetivo cambió
`source_sha256` en `plan.toml` no coincide con el actual. O repón el
fichero original o usa `quattro-crack reset --yes`.

---

## Licencia

MIT OR Apache-2.0.
