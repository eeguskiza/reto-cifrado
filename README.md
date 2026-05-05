# quattro-crack

Brute-force CUDA contra **AES-CBC + PKCS7** con MD5 + estructura de password
conocida.

> Estado: **Fase 3 + Fase 3.5 completadas**. Kernels CUDA con paridad
> CPU↔GPU validada, MD5 RFC 1321, AES-128/192/256 FIPS-197, 14 KDFs,
> plan de 42 configs CBC. Throughput sostenido medido: ~1.2 GH/s en
> RTX 5070 Ti (target spec preliminar 3 GH/s; Fase 6 optimiza —
> ver `DECISIONS.md` D-012).

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

## Modo de cifrado (confirmado)

**AES-CBC con padding PKCS7**, AES-128 ó AES-256 según la KDF (16 ó 32 B
de clave). Confirmado por el autor del reto. El proyecto **solo soporta
CBC**, no es deuda técnica (ver `DECISIONS.md` D-006).

## KDFs soportadas (14)

**Originales (Fase 2/3) — IDs 0..8**:

| ID  | Nombre        | Definición                                  | klen | AES  |
|-----|---------------|---------------------------------------------|------|------|
| 0   | `md5_utf8`    | `MD5(pw_utf8)`                              | 16 B | 128  |
| 1   | `md5_utf16le` | `MD5(pw_utf16le)`                           | 16 B | 128  |
| 2   | `md5_utf16be` | `MD5(pw_utf16be)`                           | 16 B | 128  |
| 3   | `md5x2_utf8`  | `MD5(MD5(pw_utf8))`                         | 16 B | 128  |
| 4   | `md5_dup`     | `MD5(pw_utf8) ‖ MD5(pw_utf8)`               | 32 B | 256  |
| 5   | `md5_md5rev`  | `MD5(pw_utf8) ‖ MD5(pw_utf8)[::-1]`         | 32 B | 256  |
| 6   | `md5hex_full` | hexdigest ASCII completo                    | 32 B | 256  |
| 7   | `md5hex_lo16` | primeros 16 chars del hexdigest             | 16 B | 128  |
| 8   | `pw_padded`   | `(pw_utf8 + b"\0"*16)[:16]`                 | 16 B | 128  |

**Ampliación académica (Fase 3.5) — IDs 9..13**:

| ID  | Nombre                    | Definición                                                  | klen | AES  |
|-----|---------------------------|-------------------------------------------------------------|------|------|
| 9   | `evp_md5_aes256_nosalt`   | `EVP_BytesToKey(MD5, pw, salt=None, iter=1)[..32]`          | 32 B | 256  |
| 10  | `evp_md5_aes192_nosalt`   | mismo, truncado a 24 B                                       | 24 B | 192  |
| 11  | `md5_trunc24`             | `MD5(pw) ‖ MD5(pw)[..8]`                                     | 24 B | 192  |
| 12  | `md5_md5x2_24`            | `MD5(pw) ‖ MD5(MD5(pw))[..8]`                                | 24 B | 192  |
| 13  | `md5hex_lo24`             | primeros 24 chars ASCII de `hexdigest`                       | 24 B | 192  |

IVs: `first16` (los 16 primeros B del fichero), `zeros`, `md5pw`.

Plan total: 14 KDFs × 1 modo × 3 IVs = **42 configuraciones** ordenadas
por probabilidad descendente. Las 27 originales forman prefijo estricto
del plan extendido (D-014). Ver `DECISIONS.md` D-008 y D-014.

## Validación de hit (3 pasos)

Una clave es hit confirmado solo si:

1. primeros 16 B del PT = `Leonardo da Vinc` (kernel)
2. primeros 32 B del PT = `Leonardo da Vinci\r\nLeonardo da V` (CPU)
3. padding PKCS7 del último bloque válido (CPU)

(2)+(3) descartan los falsos positivos del kernel (≈ 2⁻¹²⁸ por candidata).
Si pasa (1)+(2) pero falla (3) → bug; el runner aborta.

## Build

```bash
cargo build --release
cargo test --release
```

## Uso actual

```bash
# Inspeccionar fichero objetivo
cargo run --release -- inspect ./data/cifrado.txt

# Ver plan resuelto para cada preset
cargo run --release -- plan --preset canonical
cargo run --release -- plan --preset likely
cargo run --release -- plan --preset exhaustive

# Persistir plan en state/plan.toml (formato definitivo)
cargo run --release -- plan --preset exhaustive --save

# Ver estado actual (plan + progreso si existe)
cargo run --release -- status
```

Cuando esté Fase 4 lista:

```bash
quattro-crack run --input ./data/cifrado.txt --preset exhaustive
```

## Presets

| Preset       | Configs | Estimación |
|--------------|---------|------------|
| `canonical`  | 4       | ~1,5 h     |
| `likely`     | 12      | ~5 h       |
| `exhaustive` | 27      | ~10–15 h *(default)* |

(Estimaciones a 10 GH/s sostenidos en RTX 5070 Ti; recalibrar tras Fase 6.)

## Roadmap

- [x] Fase 0 — esqueleto + loader + `inspect`
- [x] Fase 1 — generador combinatorio CPU (crítico)
- [x] Fase 2 — KDFs + descifrado CPU + plan + estado atómico + CLI ampliada
- [x] Fase 3 — kernels CUDA (gen, MD5, AES-128/256, brute para 9 KDFs)
- [ ] Fase 4 — multi-config runner + persistencia + reanudación + tests de pausa
- [ ] Fase 5 — TUI en vivo
- [ ] Fase 6 — optimización (warp-cooperative AES, MD5 vectorizado)

## Build CUDA

Prerequisitos:
- CUDA Toolkit ≥ 12.8 (recomendado 13.0). Detectado: `nvcc --version`.
- GPU NVIDIA con compute capability ≥ 8.9 (Ada) — nativo a 12.0 (Blackwell).
- Driver compatible (en WSL2: el driver Windows expone CUDA al guest).

`build.rs` automáticamente:
- Detecta `nvcc` (PATH, `NVCC`, `CUDA_HOME`, rutas estándar).
- Comprueba si `nvcc` soporta `-arch=sm_120` (Blackwell). Si no, cae a
  `sm_89` (Ada) y emite warning `cargo:warning=Compilando para sm_89...`.
- Compila `kernels/brute.cu` **9 veces** (una por KDF) a PTX en `OUT_DIR`.
- Compila los kernels auxiliares para tests (`dump_passwords`, `md5_test`,
  `aes_test`, `force_emit_hits`).

Verificación rápida:

```bash
cargo test --release --test cpu_gpu_parity        # paridad CPU↔GPU 1M
cargo test --release --test md5_rfc1321           # MD5 RFC 1321
cargo test --release --test aes_fips197           # AES NIST FIPS-197
cargo test --release --test e2e_synthetic         # E2E + buffer hits
```

## Troubleshooting WSL2

A partir de Fase 3 hace falta `nvcc` (CUDA Toolkit) en WSL, **no solo el
driver de Windows**. Comprobar con `nvcc --version`. Si falta:

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

**No instales** `cuda-drivers-*` ni `nvidia-driver-*` en WSL: rompería la
integración con el driver de Windows.
