# quattro-crack

Brute-force CUDA contra **AES-CBC + PKCS7** con MD5 + estructura de password
conocida.

> Estado: **Fase 2 completada** (KDFs, descifrado de referencia CPU, plan de
> 27 configs, persistencia atómica, CLI ampliada). Sin CUDA aún —
> requerido a partir de Fase 3.

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

## KDFs soportadas (9)

| ID            | Definición                                  | klen |
|---------------|---------------------------------------------|------|
| `md5_utf8`    | `MD5(pw_utf8)`                              | 16 B |
| `md5_utf16le` | `MD5(pw_utf16le)`                           | 16 B |
| `md5_utf16be` | `MD5(pw_utf16be)`                           | 16 B |
| `md5x2_utf8`  | `MD5(MD5(pw_utf8))`                         | 16 B |
| `md5_dup`     | `MD5(pw_utf8) ‖ MD5(pw_utf8)`               | 32 B |
| `md5_md5rev`  | `MD5(pw_utf8) ‖ MD5(pw_utf8)[::-1]`         | 32 B |
| `md5hex_full` | hexdigest ASCII completo                    | 32 B |
| `md5hex_lo16` | primeros 16 chars del hexdigest             | 16 B |
| `pw_padded`   | `(pw_utf8 + b"\0"*16)[:16]`                 | 16 B |

IVs: `first16` (los 16 primeros B del fichero), `zeros`, `md5pw`.

Plan total: 9 KDFs × 1 modo × 3 IVs = **27 configuraciones** ordenadas por
probabilidad descendente. Ver `DECISIONS.md` D-008.

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
- [ ] Fase 3 — kernel CUDA básico (`md5_utf8/cbc/first16` AES-128)
- [ ] Fase 4 — multi-config + persistencia + reanudación + tests de pausa
- [ ] Fase 5 — TUI en vivo
- [ ] Fase 6 — optimización (opt-in)

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
