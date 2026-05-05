# quattro-crack

Brute-force CUDA contra AES + MD5 con estructura de password conocida.

> Estado: **fase 1 completada** (generador combinatorio CPU). CUDA aún no
> integrado. Requiere CUDA Toolkit en Linux/WSL2 a partir de la fase 3.

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

(Ver `DECISIONS.md` D-001 sobre la corrección del valor publicado en la
spec original.)

## Build (fase 0-1, sin CUDA)

```bash
cargo build --release
cargo test --release
```

## Uso actual

```bash
# Inspeccionar el fichero objetivo
cargo run --release -- inspect ./data/cifrado.txt
```

Salida esperada: tamaño binario, IV en hex, primeros 32 B de ciphertext y
SHA-256 del fichero base64 original.

## Roadmap

- [x] Fase 0 — esqueleto + loader + `inspect`
- [x] Fase 1 — generador combinatorio CPU (crítico)
- [ ] Fase 2 — KDFs, descifrado de referencia, plan + estado atómico
- [ ] Fase 3 — kernel CUDA básico (`md5_utf8/cbc/first16`)
- [ ] Fase 4 — multi-config + persistencia + reanudación + tests de pausa
- [ ] Fase 5 — TUI en vivo
- [ ] Fase 6 — optimización (opt-in)

Detalle completo de fases en la spec de proyecto (no committed).

## Troubleshooting WSL2

A partir de la fase 3 hace falta `nvcc` (CUDA Toolkit) instalado en WSL,
no solo el driver de Windows. Comprobar con `nvcc --version`. Si falta,
instalar el toolkit oficial para Ubuntu 24.04 (`cuda-toolkit-12-x` desde
el repo `cuda-wsl-ubuntu`).
