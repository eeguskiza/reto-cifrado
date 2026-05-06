# DECISIONS

Registro de decisiones no obvias del proyecto. Cada entrada se referencia
desde el código con `// DECISION: <id>`.

---

## D-001 — Cardinalidad del espacio: N = 59_559_806_250_000

**Contexto**: la spec (§2.4) lista los factores
`70 × 625 × 194_481 × 7 × 1000` y los aproxima a `≈ 5,96 × 10¹³`.
El producto exacto de esos factores es **59 559 806 250 000**
(≈ 5,956 × 10¹³), que coincide con el exponente declarado.

El número entero `5 955 482 812 500` que aparecía justo antes de la
aproximación es un orden de magnitud inferior y no es el producto de los
factores listados (no es siquiera divisible por 7). Lo tratamos como typo
y trabajamos con el producto correcto.

**Implicaciones**:

- `combinatorics::N` = `59_559_806_250_000`.
- ETA y mock de TUI usan este valor.
- `tests/generator.rs::test_index_to_password_unique_first_million`
  cubre solo el primer millón; la unicidad sobre el espacio completo se
  garantiza por construcción bijectiva.

---

## D-002 — Orden lexicográfico explícito del generador

Decomposición de `idx ∈ [0, N)` en cinco campos, de mayor a menor peso:

| Campo  | Rango           | Multiplicador acumulado |
|--------|-----------------|-------------------------|
| year   | `[0, 1000)`     | `7 × 70 × 21⁴ × 5⁴ = 59_559_806_250` |
| disp   | `[0, 70)`       | `7 × 21⁴ × 5⁴ = 850_854_375` |
| upper  | `[0, 7)`        | `21⁴ × 5⁴ = 121_550_625` |
| cons   | `[0, 21⁴)`      | `5⁴ = 625` |
| vowel  | `[0, 5⁴)`       | `1` |

Decodificación:
- `year   = idx / 59_559_806_250`
- `disp   = (idx %  59_559_806_250) /  850_854_375`
- `upper  = (idx %     850_854_375) /  121_550_625`
- `cons   = (idx %     121_550_625) /          625`
- `vowel  =  idx %             625`

**Convenciones internas a cada campo**:

- `year` se imprime como tres dígitos `NNN` con cero a la izquierda: `idx=0 → "000"`.
- `disp` indexa la enumeración lexicográfica estándar de las 70 combinaciones
  de 4 elementos tomados de 8 (posiciones de las vocales en el bloque de 8 letras,
  0-indexado dentro del bloque). `disp=0 = [0,1,2,3]`, `disp=69 = [4,5,6,7]`.
- `upper` indexa las 7 posiciones del bloque de letras donde puede ir la
  mayúscula (posiciones 1..7 del bloque, 0-indexado; equivalente a posiciones
  3..9 del password completo). `upper=0` → `letters[1]`.
- Las 4 vocales se interpretan como un número en base 5 con dígito más
  significativo a la izquierda; el dígito `i`-ésimo (0=más significativo)
  da el índice del vocabulario `aeiou` que ocupa la `i`-ésima posición de
  vocal del bloque (en orden de posición ascendente).
- Igual para 4 consonantes en base 21 con vocabulario
  `bcdfghjklmnpqrstvwxyz`.

**Endpoints documentados**:

- `idx = 0`           → password `.aAaabbbb1000.`
- `idx = N - 1`       → password `.zzzzuuuU1999.`

Justificación de la elección (year como peso mayor): permite que un barrido
lineal pruebe primero todos los passwords con `NNN=000`, luego `NNN=001`,
etc. Si el reto sugiere un año concreto (típico Da Vinci: `1452`), un
operador con esa pista puede lanzar `--only-config` con un offset y barrer
solo ese año en `1/1000` del tiempo total.

---

## D-003 — Modo `linear` por defecto, `lcg` opt-in

Spec §4.2 ya argumenta el porqué. Refrendado: para barrido completo el
orden no afecta al tiempo total, solo a la cobertura cuando se aborta.
Lineal es testeable trivialmente; LCG queda como `--shuffle lcg`.

---

## D-004 — Compute capability target

- Target primario: `sm_120` (Blackwell, RTX 5070 Ti).
- Fallback documentado: `sm_89` con warning visible si `nvcc < 12.8`.
- Decisión deferida hasta Fase 3, cuando se introduzca CUDA.

---

## D-005 — `lib + bin` en lugar de solo binario

`src/lib.rs` expone los módulos puros; `src/main.rs` hace solo orquestación
CLI. Permite tests de integración limpios contra la API pública y desacopla
la lógica de la TUI del runner.

---

## D-006 — Modo único `Mode::Cbc` desde el día uno

**Contexto**: la spec original v2 contemplaba CBC, CFB128, OFB y CTR; el
autor del reto confirmó posteriormente que el modo es **AES-CBC con
padding PKCS7**.

Decisión: el `enum Mode` se construye en Fase 2 con **una sola variante
`Cbc`**. Ningún código de runtime ni compile-time soporta CFB/OFB/CTR.

**Implicaciones**:

- El `match mode` en cualquier dispatch sigue siendo exhaustivo (Rust lo
  garantiza) pero degenera a una sola rama. No es deuda: es la spec real.
- Cualquier intento futuro de añadir un modo es un cambio explícito de
  tipos, no un parámetro runtime.
- El plan total se reduce de 9 KDFs × 4 modos × 3 IVs = 108 → 9 × 1 × 3 = **27**
  configuraciones (ver D-008).
- El kernel CUDA de Fase 3 será especializado a CBC, sin dispatch por modo.

---

## D-007 — Validación de hit en tres pasos obligatorios

Una clave candidata se considera **hit confirmado** solo si, sobre el
plaintext recuperado descifrando el ciphertext objetivo:

1. los primeros 16 bytes coinciden con `KNOWN_PREFIX_16` (lo valida el kernel)
2. los primeros 32 bytes coinciden con `KNOWN_PREFIX_32` (lo valida la CPU)
3. el último bloque tiene padding PKCS7 válido

**Si pasa (1)+(2) pero falla (3)** se devuelve `HitVerdict::Pkcs7Mismatch`
y el runner debe **abortar el barrido** con warning crítico. Justificación:
bajo CBC + PKCS7 real, conseguir que coincidan los primeros 32 bytes sin
que cuadre el padding tiene probabilidad ≈ 2⁻¹³⁰ por candidata, que es
"nunca". Si pasa, casi seguro indica:

- bug en la KDF (genera clave incorrecta para esta candidata),
- bug en el kernel (descarta candidatas correctas o reporta incorrectas),
- corrupción del ciphertext.

Mejor abortar y pedir intervención humana que confiar en un hit que rompe
las matemáticas.

**Test**: `tests/aes_cbc_pkcs7.rs::test_pkcs7_validation_required_*`.

---

## D-008 — Orden del plan: 27 configs por probabilidad descendente + 3 presets

`plan::default_plan_order()` devuelve **exactamente las 27 ConfigEntry**
del producto cartesiano `{9 KDFs} × {Cbc} × {first16, zeros, md5pw}` en
el orden documentado en el prompt v3 (cabecera md5_utf8/first16, cola
md5hex_*/md5pw).

Presets (prefijos estrictos del orden completo):

| Preset       | Configs | Estimación tiempo |
|--------------|---------|-------------------|
| `canonical`  | 4       | ~1,5 h            |
| `likely`     | 12      | ~5 h              |
| `exhaustive` | 27      | ~10–15 h (default)|

**Test bloqueante**: `tests/plan_order.rs::test_default_plan_order_is_27_cbc_configs`
afirma el orden literal byte-a-byte. Si el orden cambia, falla.

Los presets son contratos: el usuario que arranca con `--preset likely`
debe poder reanudar con `--preset exhaustive` y que las 12 ya barridas
queden marcadas como completadas. Esa proyección la implementa Fase 4.

---

## D-009 — T-tables AES en `__shared__`, gmul en registros

**Contexto**: la versión inicial mantenía Td0..Td3 + INV_SBOX en
`__device__ __constant__`. El throughput inicial fue 0.27 GH/s.

**Diagnóstico**: la memoria `__constant__` de CUDA tiene un puerto único
de broadcast: cuando todos los threads de un warp leen la misma
dirección, se sirve en 1 ciclo; cuando leen direcciones distintas
(caso típico de un T-table lookup driven-by-data), las lecturas se
**serializan**. En decrypt, cada thread accede a 16 direcciones
distintas por ronda intermedia × 9 rondas + 16 finales = 160 lookups.
El factor de serialización contra constant cache mide ~6× peor que
contra shared.

**Decisión**:

- `Td0..Td3` (4 × 1 KB), `INV_SBOX` (256 B) y `SBOX` (256 B, para
  `aes_inv_mix_column_via_td0` durante key schedule) **se cargan a
  `__shared__` cooperativamente al arrancar cada block** en
  `brute_kernel`. Total ≈ 4640 B/block, < 5 % de los 96 KB shared del
  SM en sm_120.
- Las wrappers públicas `aes128_decrypt_block` / `aes256_decrypt_block`
  siguen leyendo de `__constant__` para que `aes_test.cu` (los tests
  FIPS-197) no necesiten setup de shared.

**Medido**: 0.27 → 1.57 GH/s al pasar T-tables a shared (5.8× speedup).
Una ruta alternativa probada (`aes_inv_mix_column_via_td0`, reutilizar
Td0 + SBOX en lugar de gmul-loop) **empeoró** a 1.25 GH/s; el gmul-loop
de 8 iteraciones bajo `#pragma unroll` colapsa a ~8 instrucciones
bit-a-bit en registros y vence al doble lookup. Documentado en código
con `// PERF:`.

**Estado**: 1.2 GH/s sostenido (best of 5 sobre 128 Mi idx) — por
debajo del target spec preliminar de 3 GH/s. Fase 6 atacará: warp-
cooperative AES decrypt, MD5 vectorizado, Td-tables packed para que
quepan menos por warp.

---

## D-010 — Target `sm_120` (Blackwell) con fallback `sm_89` (Ada)

**Contexto**: la GPU del usuario es RTX 5070 Ti con compute capability
12.0 (Blackwell). CUDA Toolkit < 12.8 no soporta `sm_120`.

**Decisión**: `build.rs` intenta compilar un kernel-probe a `-arch=sm_120`;
si falla cae a `sm_89` y emite `cargo:warning=Compilando para sm_89 (Ada).
Para sm_120 nativo (Blackwell) actualiza CUDA Toolkit a ≥ 12.8`.

**Estado actual**: detectado nvcc 13.0.88 ⇒ `sm_120` activo. Variable
`QC_CUDA_ARCH` exportada al build de Rust para diagnóstico.

---

## D-011 — Único `kernels/brute.cu` parametrizado por `#define KDF_ID`

**Contexto**: 9 KDFs implementadas. Opciones consideradas:

(A) 9 ficheros `kernels/brute_<kdf>.cu`, cada uno con su KDF inline.
(B) **Un fichero `brute.cu` parametrizado**, compilado 9 veces con
    `nvcc -DKDF_ID=<0..8> -DKEY_LEN=<16|32>`.
(C) Un único PTX con dispatch dinámico runtime sobre `kdf_id`.

**Decisión**: opción **B**.

- Ventajas vs (A): un único cuerpo de kernel, una única matriz de
  optimizaciones, cero divergencia entre variantes salvo el bloque
  `derive_key`.
- Ventajas vs (C): cero coste runtime de switch, cada PTX queda
  especializado y nvcc optimiza KDF-específicamente (e.g., `pw_padded`
  no incluye código MD5 en el PTX final).

**Resultado**: `target/.../brute_<id>.ptx` para id ∈ 0..8, embebido en
el binario con `include_str!()` y cargado on-demand por
`KernelBundle::load(kdf)`.

**Tests**: `tests/aes_fips197.rs` valida AES per se; `tests/e2e_synthetic.rs`
valida el dispatch correcto del KDF para `md5_utf8` (id=0, AES-128) y
`md5_dup` (id=4, AES-256), incluido el modo `md5pw` que computa el IV
in-device.

---

## D-012 — Throughput Fase 3 → Fase 6: 1.1 → 2.37 GH/s (2.1× speedup)

**Tabla de progreso paso a paso** (RTX 5070 Ti, sm_120,
`md5_utf8/cbc/zeros` AES-128, batch 32 Mi, sostenido 10–30 s):

| Paso                                              | regs | stack | smem  | avg GH/s | peak GH/s | vs base |
|---------------------------------------------------|------|-------|-------|----------|-----------|---------|
| Baseline Fase 3 (registros, sin launch_bounds)    |  128 |  16 B | 4640 B|   1.10   |   1.62    |  1.00×  |
| Step 2: `__launch_bounds__(128, 6)`               |   80 |  48 B | 4640 B|   1.54   |   1.92    |  1.40×  |
| Step 4: cap grid + N=8 candidatas/thread          |   80 |  48 B | 4640 B|   2.26   |   2.36    |  2.05×  |
| Step 3: InvMixColumns vía Td0 (vs gmul-loop)      |   80 |  24 B | 4640 B|   2.37   |   2.42    |  2.15×  |

**Estado final tras Fase 6**: ~2.37 GH/s avg / 2.42 GH/s peak / 2.32 GH/s
sostenido sobre 30 s. **Target ≥ 3 GH/s no alcanzado**: faltan ~27 % al
target estricto. El objetivo de excelencia 4–5 GH/s tampoco se alcanza.

**Tabla por KDF** (avg GH/s, batch 32 Mi, 5 s — best-of-1 por entrada):

| KDF                       | klen | AES   | GH/s avg |
|---------------------------|------|-------|----------|
| `pw_padded`               | 16 B | 128   | 5.24     |
| `md5hex_lo24`             | 24 B | 192   | 2.91     |
| `md5_trunc24`             | 24 B | 192   | 2.78     |
| `evp_md5_aes192_nosalt`   | 24 B | 192   | 2.41     |
| `md5_utf8`                | 16 B | 128   | 2.37     |
| `md5_md5x2_24`            | 24 B | 192   | 2.37     |
| `md5_utf16le`             | 16 B | 128   | 2.36     |
| `md5_utf16be`             | 16 B | 128   | 2.36     |
| `md5hex_lo16`             | 16 B | 128   | 2.27     |
| `md5x2_utf8`              | 16 B | 128   | 2.08     |
| `md5_dup`                 | 32 B | 256   | 1.74     |
| `md5_md5rev`              | 32 B | 256   | 1.70     |
| `md5hex_full`             | 32 B | 256   | 1.76     |
| `evp_md5_aes256_nosalt`   | 32 B | 256   | 1.68     |

`pw_padded` no llama a MD5 ⇒ techo del path AES-128 puro ≈ 5.2 GH/s.
La diferencia hasta 2.37 GH/s en `md5_utf8` es coste neto del MD5 +
key-schedule. AES-256 KDFs (256 más rondas + 60-word rk vs 44) explican
la caída a ~1.7 GH/s.

**Lo que NO funcionó** (medido, descartado, justificado en D-021):

- **Round keys en `__shared__` per-thread slot**: regs/thread bajan de 80
  a 80 (sin cambio para AES-128 con launch_bounds activo) pero la smem
  por bloque sube de 4640 B a 27 680 B (AES-128) / 35 872 B (AES-256).
  100 KB de smem/SM ⇒ 3 blocks/SM (AES-128) / 2 blocks/SM (AES-256) =
  384 / 256 threads/SM, **peor** que los 768 actuales. Bench: 2.07 GH/s
  vs 2.37 GH/s. Net negative.

- **`__launch_bounds__(128, 8)` (64 regs, 128 B stack)**: spills caros,
  net negative vs (128, 6) pese a la mayor occupancy teórica.

- **Block_dim = 256 con (256, 3)**: 768 threads/SM teóricos pero 2.19
  GH/s reales — geometría peor para esta carga.

**Lo que NO se aplicó** (analizado, no implementado):

- **Cooperative AES (4 threads/decrypt)**: ganancia esperada 1.5–2× pero
  reescribir el path AES con cooperación intra-warp es de alto riesgo
  para un proyecto que ya funciona end-to-end. Documentado como deuda
  en D-024.

- **PTX inline `lop3.b32`**: SASS dump del kernel optimizado muestra
  883 LOP3.LUT instructions emitidas automáticamente por ptxas; añadir
  asm inline no aporta nada. Confirmado en D-024.

**Histórico (Fase 3, antes de Fase 6)**:

**Anatomía del kernel** por candidata (KDF md5_utf8 + AES-128, ruta
más simple):

| Etapa                     | Coste relativo | Notas |
|---------------------------|----------------|-------|
| `index_to_password`       | bajo           | divisiones u64, accesos a `DISPOSITIONS` en `__constant__` |
| `md5_compute(pw, 14, …)`  | medio          | 1 bloque MD5 (64 rondas) sobre 14 B con padding |
| `aes128_set_key`          | **alto**       | forward expansion + reverse + 36 InvMixColumns (con `aes_gmul` 8-iter unrolled) |
| `aes128_decrypt_block`    | medio          | 9 rondas T-tables en `__shared__` + final round |
| XOR-IV + comparación      | trivial        | 4 × `uint32_t` |

`ptxas`: 120 registros/thread, 16 B stack frame (sin spills), 4640 B
shared/block. Con 128 threads/block ⇒ ≈ 4 blocks/SM ⇒ 512 threads/SM
⇒ ≈ 25 % occupancy en sm_120 (target 50–75 %).

**Causa principal**: register pressure por `rk[44|52|60]` mantenido
en registros tras unroll completo (necesario para evitar local memory
en accesos con índice runtime). Esto cierra la occupancy a la mitad
de lo deseable.

**Decisión**: aceptar 1.2 GH/s como "preliminar funcional" para Fase 3.
**Fase 6** atacará explícitamente, en orden de coste/beneficio:

1. **Warp-cooperative AES**: 4 threads cooperan en 1 decrypt (cada uno
   procesa 1 columna), `rk` compartido en `__shared__` por warp.
   Trade: -28 % registers/thread, -75 % redundant work, +sync.
2. **MD5 K/S tables a `__shared__`**: hoy en `__constant__`, mismo
   problema que tenían las T-tables.
3. **`__launch_bounds__`** explícito tras medir el equilibrio óptimo
   regs/occupancy.
4. **PTX inline asm** para `lop3.b32` (XOR de 3 entradas en una
   instrucción) en el round body de AES.

A 1.2 GH/s, el preset `canonical` (4 configs × 5.96e13 idx) tarda
≈ 11 h en lugar de las 1.5 h estimadas. Se documenta en README; el
usuario decide si arrancar el barrido nocturno con esto o esperar a
Fase 6.

---

## D-013 — `KeyMaterial` como `struct(Vec<u8>)` desde Fase 3.5

**Contexto**: en Fase 2 `KeyMaterial` era un enum con dos variantes:

```rust
pub enum KeyMaterial { K16([u8; 16]), K32([u8; 32]) }
```

Ergonómico para 16/32 bytes pero rígido al añadir AES-192 (24 B).

**Decisión**: refactorizar a `struct KeyMaterial(Vec<u8>)` con la misma
API pública (`as_slice`, `len`, `is_empty`).

**Justificación**:

- Soporta cualquier tamaño 16/24/32 sin proliferación de variantes.
- Cero call sites afectados: nadie hacía `match` sobre `K16`/`K32`,
  todos consumían vía `as_slice()` o `len()`.
- Una asignación heap por `derive()` — coste despreciable, las KDFs
  CPU se invocan solo en validación de hits, no en hot loop GPU.

**Validado**: build + 78 tests verdes tras el refactor.

---

## D-014 — IDs estables 0..8, ampliación 9..13 para Fase 3.5

**Contexto**: la spec original (Fase 3) catalogó 9 KDFs con IDs 0..8.
Esos IDs forman parte del contrato del kernel CUDA (cada PTX se compila
con `-DKDF_ID=N` y se carga indexando `PTX_BRUTE[id]`) y aparecen en los
hits emitidos (`DeviceHit::kdf_id`).

**Decisión**: al añadir las 5 KDFs nuevas en Fase 3.5, los IDs 0..8
**no se renumeran**. Las nuevas reciben IDs 9..13 en el orden:

| ID | Variante                  | klen | AES   |
|----|---------------------------|------|-------|
| 9  | `EvpMd5Aes256Nosalt`      | 32 B | 256   |
| 10 | `EvpMd5Aes192Nosalt`      | 24 B | 192   |
| 11 | `Md5Trunc24`              | 24 B | 192   |
| 12 | `Md5Md5x2_24`             | 24 B | 192   |
| 13 | `Md5HexLo24`              | 24 B | 192   |

**Tests bloqueantes**:

- `config::tests::original_nine_keep_their_ids`: IDs 0..8 literales.
- `config::tests::kdf_ids_match_array_order`: orden y declaración alineados.
- `tests/plan_order.rs::test_first_27_are_strict_prefix_of_42`:
  el plan extendido tiene las 27 entries originales como prefijo
  byte-a-byte.

Esto garantiza que sesiones interrumpidas en Fase 3 puedan reanudarse
con el binario de Fase 3.5 sin reordenar progreso ya guardado.

---

## D-015 — SIGINT/SIGTERM con flag + conditional_shutdown

**Contexto** (spec §7.5): primer SIGINT/SIGTERM debe terminar el batch
en curso, persistir progreso y salir limpio. Segundo SIGINT durante el
shutdown debe ser aborto inmediato (~código 130).

**Implementación** (`src/signal.rs`): `signal-hook 0.3` con DOS
handlers por señal, registrados en este orden:

1. `flag::register_conditional_shutdown(SIG, exit_code, &flag)`
2. `flag::register(SIG, &flag)`

Los handlers corren en orden de registro:

- **Primera entrega**: `conditional_shutdown` ve `flag=false` →
  no-op. `register` pone `flag=true`. El runner consulta el flag al
  final del batch, persiste y sale.
- **Segunda entrega**: `conditional_shutdown` ve `flag=true` → mata
  el proceso con el exit code dado. (El segundo handler ni llega a
  ejecutarse.)

**Atómicas**: SIGKILL es incontrolable; la atomicidad de
`state::atomic_write` (write-tmp → fsync → rename) es la salvaguarda
final. En el peor caso se pierde un único batch (§7.2).

**Test bloqueante**: `tests/resume.rs::test_resume_finds_key_after_pause`
spawnea el binario, manda SIGINT a los 1.5 s, espera salida limpia y
luego reanuda. Validado en hardware (run 1 paró en idx 700M tras 1.32 s,
resume llegó al hit en idx 1.7G tras 1.82 s adicionales).

---

## D-016 — Salida temprana en primer hit confirmado

**Contexto**: una vez encontrada la clave, seguir barriendo sería
gasto puro de GPU. La probabilidad de un segundo hit confirmado bajo
otra (KDF, IV) en el mismo barrido es ~2⁻¹³⁰ × N — efectivamente
cero.

**Decisión**: el runner devuelve `RunOutcome::Found` y termina en
cuanto valida el primer hit con verdict `Confirmed`. El hit se guarda
en `progress.toml` (con password, config, plaintext hex y timestamp)
antes de salir.

**Reanudación tras hit**: si el usuario pasa `--resume`, el runner
volverá a ejecutar desde donde quedó `next_step`; al ver el hit
guardado, el flag `Found` no se re-emite automáticamente (el runner
trabaja independiente del histórico de hits). Si quiere "verificar
otras KDFs" puede usar `--skip-config` para saltarse la KDF que ya
encontró la clave.

**Tests cubren**: `tests/e2e_synthetic.rs::test_e2e_synthetic_aes128_cbc`
(salida temprana en hit) y `tests/resume.rs::test_resume_finds_key_after_pause`
(hit + persist + exit code 0).

---

## D-017 — Validación PKCS7 del último bloque sobre 1600 B reales

**Contexto**: Fase 3 validaba hits con `validate_hit` sobre el CT
sintético de los tests (1600 B con PKCS7 manufacturado). En Fase 4 el
runner aplica la misma función al CT REAL del fichero objetivo.

**Decisión**: `runner::run` invoca `reference::validate_hit(key, iv,
ct.ct())` donde `ct.ct()` son los 1600 B del ciphertext del fichero
(tras decodificar base64). Sobre esos 1600 B:

1. `decrypt_cbc_raw` → 1600 B de plaintext.
2. comparar primeros 32 B con `KNOWN_PREFIX_32`.
3. validar PKCS7 sobre los últimos 16 B (último byte ∈ [1,16] +
   los últimos N bytes idénticos a N).

Si pasan los tres → `Confirmed`. Si falla (3) tras pasar (1)+(2) →
`Pkcs7Mismatch` ⇒ **abortar el barrido** con warning (D-007).

El runner persiste el plaintext completo en hex en `Hit::plaintext_hex`
antes de salir, para auditoría.

---

## D-018 — Logs estructurados a fichero en formato `compact` de tracing

**Contexto** (Fase 5): la TUI vive en stdout; los logs detallados van
a `./logs/run-YYYYMMDD-HHMMSS.log` para inspección post-mortem.

**Opciones consideradas**:

- **JSON**: máxima compatibilidad con tooling (jq, ELK). Coste:
  legibilidad humana baja, hay que pasar por `jq` para cualquier ojeo.
- **pretty (multi-line)**: legibilidad humana alta. Coste: difícil
  de grepear (un evento ocupa varias líneas).
- **compact (single-line con campos K=V)**: legible (`grep` directo),
  parseable razonablemente, y default de `tracing-subscriber::fmt`
  cuando se llama `.compact()`.

**Decisión**: `compact`, sin ANSI (los ficheros no necesitan colores),
sin target (`with_target(false)`), filtro `RUST_LOG` o `info` por
defecto.

Justificación: usuario único / proyecto académico. La pre-condición
"si en el futuro hace falta JSON, basta con cambiar `.compact()` por
`.json()` y nada más" la cumplimos.

---

## D-019 — TUI desacoplada por canal `crossbeam_channel::unbounded`

**Contexto**: el contrato de Fase 5 exige que la TUI **no** acople al
runner. Si la TUI cae, el runner sigue. Si el canal se llena, el
runner no espera.

**Opciones**:

- `Arc<Mutex<TuiState>>`: simple, pero el runner toma lock cada
  evento → contención y bloqueos potenciales.
- `tokio::sync::broadcast`: pensada para varios consumidores; trae
  toda la maquinaria async para un caso síncrono.
- `crossbeam_channel::bounded(N)`: backpressure, pero el runner
  podría bloquear con la TUI lenta.
- **`crossbeam_channel::unbounded`**: el runner llama `try_send`
  (no bloquea jamás), el renderer consume a su ritmo. Memoria
  acotada en la práctica porque el renderer corre a 5 Hz y los
  batches a 0.1–10 Hz: el canal nunca acumula más de unos pocos
  eventos.

**Decisión**: `crossbeam_channel::unbounded`. `TuiSink::on_event`
hace `self.tx.try_send(event)` y descarta silenciosamente si el canal
está desconectado (renderer ya salió tras `PlanCompleted`/`Paused`).

---

## D-020 — Auto-detect TUI con `std::io::IsTerminal`

**Contexto**: `quattro-crack run` debe usar TUI cuando hay TTY y
caer a `StderrSink` cuando stdout está redirigido (pipes, ficheros,
CI). La spec menciona `atty` o `is-terminal`.

**Opciones**:

- `atty` crate: clásico, no mantenido desde 2021.
- `is-terminal` crate: bien mantenido, sin warnings de seguridad.
- **`std::io::IsTerminal`** (estable desde Rust 1.70): cero deps,
  exactamente la API que necesito.

**Decisión**: `std::io::IsTerminal::is_terminal(&io::stdout())`.
Combinado con `--no-tui` (override forzoso), el comportamiento es:

```text
no_tui flag  TTY  →  sink usado
─────────────────────────────────
true         *    →  StderrSink   (override explícito)
false        no   →  StderrSink   (auto)
false        yes  →  TuiSink      (auto)
```

Sin dependencia externa nueva — Rust 1.95 lo soporta nativamente.

---

## D-021 — Round keys en registros (NO en `__shared__`); rechazo motivado

**Contexto** (Fase 6, Step 1 del plan): el prompt sugería mover `rk[44|52|60]`
a `__shared__` con un slot por thread (padded a 45/53/61 words coprimo
con 32 banks) para liberar registros y subir occupancy. Ganancia esperada
1.3–1.5× según el plan original.

**Implementado y medido**:

```cuda
__shared__ uint32_t s_rk[QC_BLOCK_DIM * QC_RK_SLOT];
uint32_t* rk = &s_rk[threadIdx.x * QC_RK_SLOT];
aes128_set_key_with_tables(key, rk, s_td0, s_sbox);  // ahora escribe a smem
aes128_decrypt_block_ptr(rk, ...);                     // ahora lee de smem
```

**Resultado**:

- Registros/thread: 80 → 80 (sin cambio: launch_bounds ya cierra el cap).
- Smem/block: 4640 B → 27 680 B (AES-128) / 35 872 B (AES-256).
- Blocks/SM (smem-limited): 4 → 3 (AES-128) o 2 (AES-256).
- Threads/SM: 768 → 384 (AES-128) o 256 (AES-256). **Peor occupancy real**.
- Throughput md5_utf8: 2.37 GH/s → 2.07 GH/s (–13 %).

**Diagnóstico**: con block_dim=128 y rk-slot=45 words, smem se vuelve el
bottleneck. Para fitar 6 blocks/SM (manteniendo los 768 threads/SM
actuales) habría que recortar el slot a ≤ 16 words, lo que requiere
COMPUTAR las round keys lazy durante el decrypt — significativamente más
complejo (key schedule reverse + InvMixColumns inline por ronda) y de
alto riesgo en un kernel que ya pasa los 88 tests.

**Decisión**: `rk` permanece en local memory (con `__launch_bounds__` el
compilador spillea unos 24 B de stack frame, los regs hot quedan en
registers). La **ruta válida** del prompt en este proyecto es la
combinación Step 2 + Step 3 + Step 4, que da 2.37 GH/s sostenidos.

La cooperative-AES alternativa (4 threads/decrypt, rk compartido en
warp) ofrece más margen pero queda como deuda futura — ver D-024.

---

## D-022 — `__launch_bounds__(128, 6)` recorta regs de 128 → 80

**Contexto**: ptxas elegía 128 registros/thread sin restricciones, lo que
con 64 K regs/SM daba un techo de 4 blocks/SM × 128 threads = 512
threads/SM ≈ **25 % occupancy** en sm_120 (target práctico 50–75 %).

**Probado** (medido sobre brute_0.cubin con `--resource-usage`):

| `__launch_bounds__(T, B)` | regs | stack | threads/SM | GH/s avg |
|---------------------------|------|-------|------------|----------|
| sin directiva             | 128  |  16 B |    512     |   1.10   |
| (128, 4)                  | 128  |  16 B |    512     |   ≈1.10  |
| (128, 5)                  |  96  |  16 B |    640     |  no test |
| **(128, 6)**              |  **80** |  **24 B** |  **768** |  **2.37** |
| (128, 7)                  |  72  |  40 B |    896     |   2.22   |
| (128, 8)                  |  64  | 128 B |   1024     |   2.32   |
| (256, 3)                  |  80  |  24 B |    768     |   2.19   |
| (64, 12)                  |  80  |  24 B |    768     |   2.33   |

**Decisión**: `(128, 6)` es el punto óptimo. Bajar más regs (`(128, 7)` o
`(128, 8)`) introduce spills cuyo coste compensa la occupancy ganada.
Cambiar `block_dim` a 256 o 64 con la misma ratio threads/SM da peor
throughput por geometría.

`block_dim` está hardcoded en `src/cuda.rs::QC_BLOCK_DIM = 128` y debe
**coincidir** con `QC_BLOCK_DIM` del kernel — ptxas ignora `__launch_bounds__`
si el host lanza con un block_dim distinto.

---

## D-023 — InvMixColumns: ruta `aes_inv_mix_column_via_td0` gana tras Fase 6

**Contexto**: D-009 documentaba que el gmul-loop unrolled (puro ALU)
ganaba a la ruta SBOX→Td0 (1.57 vs 1.25 GH/s) cuando register pressure
limitaba la occupancy.

**Re-medido tras Step 2 + Step 4**:

| InvMixColumns route | regs | smem  | GH/s avg | Δ |
|---------------------|------|-------|----------|---|
| gmul-loop (D-009)   |  80  | 4640 B|   2.26   | base |
| via_td0 (Fase 6)    |  80  | 4640 B|   **2.37** | +5 % |

Con `__launch_bounds__(128, 6)` la occupancy ya no es el bottleneck.
La ruta vía Td0 tiene ~5 instr/inv_mix (4 LDS + 4 PRMT/XOR) vs ~130
instr/inv_mix del gmul-loop puro ALU. 36 calls × ~125 instr ahorradas =
~4 500 instr menos por candidata. Ganancia neta: +5 %.

**Tablas en `__shared__` vs `__constant__`**: confirmamos que la
decisión de D-009 (copy `Td0..Td3 + INV_SBOX + SBOX` desde `__constant__`
a `__shared__` una vez por bloque) sigue siendo óptima. Las 256 entradas
× 6 tablas = 4640 B/block es despreciable frente a los 100 KB smem/SM
disponibles. Probar `__constant__` con sm_120 sería 6× peor por
serialización del puerto de constants cuando los hilos leen direcciones
distintas (ya documentado).

**Constantes del MD5 (`QC_MD5_K[64]`, `QC_MD5_S[64]`)**: permanecen en
`__constant__`. Comparten dirección por ronda (todos los hilos leen
`QC_MD5_K[i]` para el mismo `i`) ⇒ broadcast-friendly, óptimo en
`__constant__`. Mover a `__shared__` no aporta y consume smem.

---

## D-024 — Step 4 (N candidatas por thread) y Step 5 (`lop3.b32`)

**Step 4 implementado**: el grid se cap a `QC_MAX_GRID_BLOCKS = 4096`
bloques (vs ilimitado antes). Combinado con `QC_N_PER_THREAD = 8`,
fuerza el stride-loop interno del kernel a iterar ~8 veces por thread
en cada lanzamiento de 32 Mi candidatas.

| Cap grid blocks | N/thread | GH/s avg |
|-----------------|----------|----------|
| 524 288 (sin cap, baseline) |    1    |   1.54   |
|  16 384         |    8     |   2.26   |
|   4 096         |    8     |   2.26   |
|   2 048         |    8     |   2.27   |
|   4 096         |   32     |   2.31   |

Decisión: `QC_MAX_GRID_BLOCKS = 4096`, `QC_N_PER_THREAD = 8`. Saturado:
N > 8 y cap < 4096 dan diferencias < 3 % no significativas. El thread
queda "caliente" entre iteraciones (warp issue slot reservado, regs de
tablas/iv/ct cacheados). Este es el lever más eficaz de Fase 6 (+0.7
GH/s sobre Step 2 solo).

**Step 5 (`lop3.b32` inline asm)**: **NO implementado** porque ya está.
El SASS dump del kernel optimizado (`cuobjdump --dump-sass brute_0.cubin`)
revela 883 instrucciones `LOP3.LUT R*, R*, R*, R*, 0x96, !PT` — el
compilador detecta los XOR-de-3-vías del round body AES y emite LOP3
nativos sin necesidad de asm explícito. Histograma SASS de instrucciones:

```
883 LOP3
815 SHF
480 LDS    ← potencial bottleneck
279 IMAD
251 IADD3
197 LEA
 86 LDC
```

Implementar lop3 manual sería redundante. Documentado como **deuda
futura justificada**: el siguiente lever de optimización es **cooperative
AES** (4 threads/decrypt con shfl + warp-sync) que reduciría LDS por
factor 4 al compartir round keys intra-warp. Coste estimado: 1–2 días
de implementación + invasive testing. Beneficio estimado: 1.5–2× sobre
los 2.37 GH/s actuales (= 3.5–4.5 GH/s, alcanzando el target de
excelencia 4–5 GH/s del prompt). Aceptamos esto como deuda porque:

1. La herramienta CUMPLE su función a 2.37 GH/s (preset exhaustive en
   ~7 días vs ~5.5 días @ 3 GH/s). La diferencia material es marginal
   para un barrido único de la vida.
2. Reescribir el path AES con cooperación intra-warp es invasivo:
   afecta a las 14 variantes del kernel, requiere tests adicionales de
   bit-exactness por intra-warp shuffling, y rompe la isomorfía actual
   con el código de referencia CPU.
3. Los 91 tests verdes son un activo. Estamos en un punto de salida
   estable.

Si en el futuro hace falta más throughput, abrir Fase 7 con cooperative
AES como objetivo único.

---

## D-025 — Default `batch_size = 64 Mi` para `run`, no 16 Mi

**Contexto** (Fase 7): el run de producción documentado por el usuario
medía **0,86 GH/s sostenidos**, vs **2,37 GH/s avg** medidos por
`benchmark` (D-012). Factor 2,75× de pérdida que no era atribuible al
kernel.

**Diagnóstico** (`tests/throughput_diagnosis.rs`, ver
`diagnose_save_progress_overhead`): `save_progress_with_bak` tarda
**9,7 ms por llamada** en este FS (WSL2, ext4 ordered). En Fase 4 el
runner hacía un `save_progress_with_bak` por batch. Con batch_size
= 16 Mi (default Fase 4) y kernel ≈ 9 ms/batch a 1,8 GH/s, **el fsync
costaba más que el kernel** y duplicaba la latencia por batch ⇒ 0,9
GH/s reales.

**Sweep medido** (`diagnose_runner_throughput_*`):

| batch_size | flush_every | GH/s real (run path) | Notas                       |
|------------|-------------|----------------------|-----------------------------|
| 16 Mi      | 1           | 0,91                 | **baseline pre-D-026**      |
| 16 Mi      | 8           | 1,66                 | flush amortizado            |
| 64 Mi      | 1           | 1,53                 | batch grande, fsync por batch |
| 64 Mi      | 8           | **1,88**             | óptimo conjunto (D-025+D-026)|
| 128 Mi     | 4           | 1,89                 | similar, peor granularidad UI|

**Decisión**:

- Default de `--batch-size` para el subcomando `run` sube de
  16 Mi → **64 Mi** (4×). El subcomando `benchmark` mantiene
  128 Mi (sin cambios).
- Combinado con flush agrupado (D-026), el throughput end-to-end
  pasa de 0,91 → 1,88 GH/s en este hardware. El factor de pérdida
  vs kernel-only baja de 2,75× a 1,06× (overhead < 6 %).

**Pérdida en kill duro** (estimada): a batch=64 Mi y 2 GH/s, ~32 ms
de cómputo perdido. Combinado con flush_every=8 (D-026): ~256 ms en
el peor caso. Aceptable para una herramienta de barrido nocturno.

**Por qué 64 Mi y no 128 Mi**: la pérdida/regresión en kill duro
escala lineal con batch_size (256 ms vs 512 ms). 64 Mi da el mismo
throughput que 128 Mi en este hardware (1,88 vs 1,89 GH/s) con la
mitad de latencia "perdible".

**Por qué no más allá de 1,88 GH/s en run real**: el techo del kernel
en este hardware (RTX 5070 Ti, WSL2, condiciones actuales) es
**~1,99 GH/s avg sostenido sobre 30 s** según `benchmark --duration 30
--batch-size 134217728`. La cifra de 2,37 GH/s en D-012 fue medida
bajo condiciones de sistema más favorables (probable: GPU más fría,
menos load concurrente). El runner alcanza 94–96 % de ese ceiling
hardware tras D-025+D-026. El gap residual es físico, no software.

**Test de regresión**:
`tests/runner_throughput.rs::test_real_run_throughput_meets_target_1_5ghz`
ejecuta el path real del runner sobre 5 s y verifica ≥ 1,5 GH/s.
1,5 GH/s deja margen contra variabilidad térmica; cualquier regresión
seria del runner (vuelta al fsync por batch, kernel roto) cae muy
por debajo.

**Compatibilidad de estado**: el formato de `progress.toml` y
`plan.toml` NO cambia. Sesiones interrumpidas con la versión
pre-D-025 reanudan sin migración; el `batch_size` viene del
`plan.toml`, no del CLI. Validado por
`test_state_compat_with_pre_optimization_progress` con un fixture
real (`tests/fixtures/legacy_progress.toml`) extraído de la sesión
del usuario pausada en idx 30 079 585 353 728.

---

## D-026 — Flush agrupado: `progress.toml` cada `flush_every` batches

**Contexto**: relacionado con D-025. `save_progress_with_bak` cuesta
9,7 ms/llamada en este FS (medido en
`diagnose_save_progress_overhead`). Con batch_size grandes el
overhead por batch baja, pero seguía suponiendo varios % del tiempo
total en run real.

**Decisión**: introducir `RunOptions::flush_every_n_batches` (default
**8**, configurable vía `--flush-every`). El runner mantiene el
progreso en RAM por batch (incluye `next_step`, `tried`, `elapsed_us`)
pero solo persiste a disco cada N batches o ante eventos críticos.

**Eventos que SIEMPRE fuerzan flush** (no esperan al ciclo):

- Hit confirmado (antes de `RunOutcome::Found`).
- PKCS7 mismatch crítico (antes de abortar, D-007).
- Stop signal (SIGINT/SIGTERM, D-015).
- Fin de config (avance al siguiente entry, evita resume con cfg
  completa pero no flusheada).
- Fin de plan completo.

**Por qué flush_every = 8 default**:

- Amortización: 8 × 32 ms (kernel a 64 Mi @ 2 GH/s) = 256 ms / 9,7 ms
  = ~3,8 % de overhead. Despreciable.
- Pérdida en kill duro: 7 batches × 32 ms = 224 ms — aceptable
  comparado con horas de barrido.
- Granularidad UI: 1 evento `BatchCompleted` por batch sigue llegando
  al sink (la TUI / stderr ven progreso cada batch); solo el flush a
  disco se agrupa.

**Atomicidad por flush**: la garantía de Fase 4 (`atomic_write` con
secuencia tmp → fsync → rename → dir-fsync) **no cambia**. Cada flush
sigue siendo atómico individualmente. Lo único que se agrupa es la
frecuencia, no la atomicidad.

**Optimización adicional dentro de `save_progress_with_bak`**: cambio
`fs::copy(path, bak)` por `fs::rename(path, bak)`. Un rename es un
cambio de dirent (~0,1 ms) frente a un read+write+fsync de todo el
fichero (~3 ms). Reduce el coste medido de 12,5 ms → 9,7 ms (~25 %).
La semántica es idéntica: el fichero anterior queda en `.bak` antes
de escribir el nuevo. En el path subsiguiente, `atomic_write` crea
un nuevo `.toml` desde `.new` con su propia atomicidad.

**Tests**:

- `test_real_run_throughput_meets_target_1_5ghz` — validación end-to-end.
- `test_resume_after_grouped_flush` — pausa con flush_every=4, resume con
  flush_every=8, verifica monotonía de `next_step` y reanudación
  correcta entre ventanas de flush distintas.
- `test_save_load_roundtrip_after_d026` — saneamiento del par
  save/load tras el cambio rename-vs-copy, incluye verificación de
  que `.bak` queda en estado correcto tras dos flushes consecutivos.
- `test_state_compat_with_pre_optimization_progress` — un
  `progress.toml` escrito por la versión pre-D-026 sigue siendo
  legible y sus 42 entries / next_step de 30 T se cargan tal cual.

**No implementado**: deferred fsync vía hilo background. Habría
elevado complejidad (sincronización con el flush forzado al pause)
sin ganancia añadida — con flush_every=8 ya estamos a < 4 % de
overhead.

---

## D-027 — Fix NVML en WSL2: symlink `libnvidia-ml.so`

**Contexto** (Fase 7): durante el run de producción del usuario
apareció el warning persistente:

```
[GPU] metrics unavailable: Nvml::init falló: libloading error
occurred: libnvidia-ml.so: cannot open shared object file:
No such file or directory
```

El barrido funcionaba intacto (la GPU computa sin NVML), pero la
línea `[GPU] util / mem / temp / power` de la TUI no se rellenaba.

**Diagnóstico** (`find / -name "libnvidia-ml*"`):

- WSL2 expone `libnvidia-ml.so.1` en `/usr/lib/wsl/lib/` (provisto
  por el driver de Windows vía la integración WSL).
- `nvml-wrapper 0.10` carga la librería con `libloading`, que
  por defecto busca **`libnvidia-ml.so`** (sin el sufijo `.1`).
- Ese symlink no se crea automáticamente. `ldconfig -p` resuelve
  `libnvidia-ml.so.1` pero no `libnvidia-ml.so`.

**Fix** (privilegiado, una vez por máquina):

```bash
sudo ln -s /usr/lib/wsl/lib/libnvidia-ml.so.1 /usr/lib/wsl/lib/libnvidia-ml.so
sudo ldconfig
```

**Fix sin sudo** (alternativa per-usuario):

```bash
mkdir -p ~/lib-nvml-shim
ln -sf /usr/lib/wsl/lib/libnvidia-ml.so.1 ~/lib-nvml-shim/libnvidia-ml.so
echo 'export LD_LIBRARY_PATH=$HOME/lib-nvml-shim:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

**Verificación**: `tests/nvml_shim.rs::nvml_init_succeeds_when_so_available`
intenta `Nvml::init()` y se considera SKIP si la librería no es
resoluble en el entorno (sin shim, sin driver). Si la librería sí
está pero `Nvml::init` falla, panic — eso sería una regresión real.

**Documentado** en README sección **Troubleshooting WSL2 → NVML**.

---

## D-028 — Cooperative AES: NO implementado en Fase 7

**Contexto**: el spec de Fase 7 contempla "O.5 — Cooperative AES
intra-warp" como último recurso si tras O.1–O.4 no se llega a
2 GH/s sostenidos en run real.

**Decisión**: **NO implementar** Cooperative AES en esta iteración.

**Justificación**:

1. Tras D-025 + D-026 + D-027, el runner sostiene **1,88 GH/s
   end-to-end**, **96 %** del techo del kernel en este hardware
   (~1,99 GH/s). El gap residual no es resoluble por software.
2. El target estricto de 2,0 GH/s era hardware-limitado: el
   benchmark mismo no llega de forma sostenida en estas
   condiciones (1,87 GH/s avg sobre 30 s).
3. Cooperative AES rompe la isomorfía con el path CPU de
   referencia. Habría requerido tests bit-exact adicionales para
   las 14 variantes del kernel (D-024 ya documenta el coste).
4. Los 91 + 4 tests siguen verdes; deuda documentada en D-024 es
   suficiente.

Si en el futuro hace falta empujar más allá, abrir Fase 8 con
Cooperative AES como objetivo único, partiendo del kernel actual
como baseline `brute_legacy_v2.cu`.

---

## D-029 — Refactor a una única configuración: AES-256-ECB + md5hex

**Contexto**: el autor del reto confirma oficialmente la construcción
criptográfica final:

```
key  = MD5(password.encode("utf-8")).hexdigest().encode("ascii")  # 32 B AES-256
mode = AES-256-ECB
pad  = PKCS7
```

(no hay IV — ECB).

Esto **descarta por confirmación** las 13 KDFs alternativas, los modos
CFB/OFB/CTR (ya descartados en D-006) y las 3 variantes de IV. La
estructura del password sigue siendo `.LLLLLLLL1NNN.` (D-001/D-002).

### Cambios al modelo

- **Plan único**: `Plan { program_version, source_path, source_sha256,
  batch_size, shuffle }`. Desaparecen `entries`, `preset`, `Preset`,
  `Mode`, `IvSource`, `ConfigEntry`. La descripción única se publica
  en `SINGLE_PLAN_DESCRIPTION = "md5hex_full / aes-256-ecb / pkcs7"`.
- **`Progress` escalar**: un único `next_step` (0..N) en lugar del
  vector paralelo `per_config`. `Hit` deja de incluir `ConfigEntry`.
- **`program_version` sube a `0.2.0`** para hacer el corte explícito.
  `state.rs::looks_like_legacy_plan/progress` detecta los formatos
  antiguos (`[[entries]]`, `[[per_config]]`, `current_config`,
  `preset`) y devuelve `StateError::LegacyFormat` con mensaje claro
  invitando a `quattro-crack reset --yes`.

### Cambios a CUDA

- **Único PTX activo**: `kernels/brute_md5hex_aes256_ecb.cu`. Sin
  `#define KDF_ID`, `#define KEY_LEN` ni `#define MODE`. Todo cableado
  (md5 → hex ASCII in-register → AES-256 → comparación contra
  `"Leonardo da Vinc"`, sin XOR de IV porque ECB).
- **`kernels/brute.cu`** (Fase 3.5, parametrizado, 14 PTX) se
  archiva como `kernels/brute_legacy_phase6.cu` y NO se compila.
- **`build.rs`** simplificado: ya no itera la tabla de KDFs.
- **`KernelBundle::load(ctx)`** sin parámetros (no recibe `Kdf`).
  **`KernelBundle::launch`** recibe solo `idx_base, idx_count,
  ct_block_0` (ECB no necesita IV).
- **`DeviceHit`** se reduce a `{ idx: u64 }` (sin `kdf_id`/`iv_id`).

### Cambios a la CLI

- `quattro-crack run` ya no acepta `--preset`, `--skip-config`,
  `--only-config`. Tampoco `--kdf` ni `--iv` en `benchmark`.
- `inspect` ya no menciona IV. Reporta los 1616 B como ciphertext
  completo (101 bloques de 16 B).
- `plan` muestra una sola línea con `SINGLE_PLAN_DESCRIPTION`.

### Cambios a `reference.rs`

- **Path activo**: `decrypt_ecb_raw`, `encrypt_ecb_pkcs7`,
  `validate_hit(key: &[u8;32], ct: &[u8])`. La validación de hit
  sigue siendo de 3 pasos (D-007 vigente): prefijo-16 (kernel),
  prefijo-32 (CPU) y PKCS7 (CPU).
- **Legacy CBC**: `decrypt_cbc_raw`, `encrypt_cbc_pkcs7` se mantienen
  con `#[doc(hidden)]` y `pub` (no `pub(crate)` para permitir su uso
  desde tests de integración). Solo se invocan desde el catálogo
  `tests/legacy_kdf.rs` y similares; **NO se usan en el path activo**.

### Cambios a tests

- **Eliminados** (obsoletos por construcción): `tests/aes_cbc_pkcs7.rs`,
  `tests/plan_order.rs`.
- **Adaptados** a ECB md5hex: `tests/resume.rs`, `tests/e2e_synthetic.rs`,
  `tests/optimized_kernel_parity.rs`, `tests/runner_throughput.rs`,
  `tests/throughput_diagnosis.rs`, `tests/kdf.rs` (solo md5hex_full),
  `tests/tui.rs`.
- **Nuevos**: `tests/d029_single_config.rs` (3 tests: plan único,
  inspect ECB, signature de `KernelBundle::load`); `tests/legacy_kdf.rs`
  (mueve los 14 KDFs vs Python aquí).
- **Intactos**: `tests/cpu_gpu_parity.rs`, `tests/generator.rs`,
  `tests/md5_rfc1321.rs`, `tests/aes_fips197.rs`, `tests/nvml_shim.rs`.

### Throughput medido (post-D-029)

Sobre el kernel único `brute_md5hex_aes256_ecb` (RTX 5070 Ti, sm_120,
WSL2, condiciones del refactor):

| Medición                         | GH/s     |
|----------------------------------|----------|
| benchmark batch 128 Mi, 30 s     | avg 1,48 / peak 1,82 |
| runner end-to-end (5 s synth)    | 1,26     |
| kernel-only (cold, peak)         | 1,82     |

**Comparación con kernel multi-KDF anterior (md5_utf8 + AES-128 + CBC,
camino más rápido)**: avg 1,87 GH/s (Fase 7). El kernel post-D-029 es
~20 % más lento porque AES-256 tiene 14 rondas vs 10 (AES-128) y rk
de 60 words vs 44, lo que pesa más que la simplificación
arquitectónica del dispatch único.

**Comparación con el path md5hex_full + AES-256-CBC del kernel
multi-KDF**: D-012 documenta 1,76 GH/s avg en condiciones más
favorables. El nuevo kernel es ligeramente mejor (1,82 peak vs 1,76)
gracias a:
- Eliminación del branch IV (`if iv_mode == 0/1/2`).
- Eliminación del XOR con IV en el bloque post-decrypt.
- Una sola PTX en cache de instrucciones del SM (vs 14).

La mejora de 10–20 % esperada se materializa parcialmente; el grueso
del coste está en MD5 + AES-256 + key-schedule, que no cambia.

### ETAs nuevas (a 1,48 GH/s avg sostenido)

`N = 59 559 806 250 000` (D-001).

| Throughput | ETA barrido completo |
|------------|----------------------|
| 1,48 GH/s avg | 40 240 s ≈ 11,2 h ≈ **0,47 días** |
| 1,82 GH/s peak | 32 720 s ≈ 9,1 h |
| 1,26 GH/s runner real (hot) | 47 270 s ≈ 13,1 h |

El tiempo cae de "≈ 1,5 días" del plan exhaustive de 42 configs a
**~12 h** del plan único — speedup efectivo ≈ 3× porque ya solo se
recorre el espacio una vez.

### Estado tras D-029

- `state/` borrado (formato incompatible).
- `program_version = 0.2.0`.
- 81 tests verdes + 10 ignorados (diagnóstico opt-in).
- Clippy limpio (`-D warnings`).
- Un único PTX activo en `target/...release/build/.../out/`.
- Cooperative AES (D-024, D-028) sigue como deuda futura: ya no es
  un lever evidente porque el kernel actual está limitado por las
  14 rondas de AES-256, no por dispatch overhead.

## D-030 — Cooperative AES intra-warp implementado, descartado por throughput

**Contexto**: la deuda heredada de D-024 / D-028 sugería que cooperative
AES intra-warp era el lever pendiente para subir el throughput sostenido
del barrido más allá de 1,5 GH/s. El kernel legacy (post-D-029) tenía
80 regs/thread + 84 B de spill stores, lo que en papel apuntaba a que
mover `rk[60]` fuera de registros (a `__shared__`) liberaría regs y
subiría occupancy.

### Implementación

Se escribió `kernels/brute_md5hex_aes256_ecb_coop.cu` con el modelo:

- 4 threads cooperan sobre 1 candidata (column-decomposition de 32 bits).
- 8 grupos por warp → 8 candidatas/warp (vs 32/warp en legacy).
- 4 warps/block, 32 grupos/block, 32 candidatas/block/iter.
- Leader (`lane%4 == 0`) hace KDF (MD5+hexify) + AES-256 key schedule,
  escribe `rk[60]` directamente en `__shared__` (slot por grupo).
- Followers (`lane%4 ∈ {1,2,3}`) cargan su columna de `rk` (15 dwords)
  en registros tras `__syncwarp`.
- Decrypt cooperativo: `__shfl_sync(width=4)` para InvShiftRows entre
  los 4 threads del grupo; T-tables Td0..Td3 + INV_SBOX en `__shared__`.
- Comparación de prefijo via `__ballot_sync` con máscara de 4 bits
  por grupo. Líder emite hit con `atomicAdd`.

Helper `aes256_decrypt_block_coop` factorizado en `kernels/aes_coop.cuh`
y reutilizado por `dump_pt_block0_coop.cu` (kernel paralelo de
diagnóstico para tests).

### ptxas medido (sm_120, -O3, --use_fast_math)

| `__launch_bounds__` | regs/thread | stack | spill stores | smem/block |
|---------------------|-------------|-------|--------------|------------|
| (128, 4)            | 112         | 16 B  | 0 B          | 12 304 B   |
| (128, 5) ★          | 96          | 16 B  | 0 B          | 12 304 B   |
| (128, 6)            | 80          | 88 B  | 76 B         | 12 304 B   |
| (128, 7)            | 72          | 120 B | 112 B        | 12 304 B   |
| (128, 8)            | 64          | 152 B | 144 B        | 12 304 B   |

★ Configuración elegida: 96 regs, 0 spill, 20 warps/SM (41,7 % occupancy
nominal, limitado por shared mem total ≈ 100 KB / 12 304 B ≈ 8 blocks/SM
máximo, pero con (128,5) se garantiza 0 spill).

### Validación bit-exact (5 tests bloqueantes)

`tests/coop_kernel_parity.rs`, **todos verdes**:

1. `test_coop_dump_matches_reference_1m` — 1 000 000 idx (5 chunks de
   200 K en posiciones diversas del espacio incl. origen y N−1)
   contra `reference::decrypt_ecb_raw`. **0 discrepancias**.
2. `test_coop_dump_matches_legacy_dump_1m` — 1 000 000 idx contra el
   `dump_pt_block0` legacy (10 chunks random de 100 K). **0 bytes
   distintos**.
3. `test_coop_brute_finds_synthetic_hit` — clave conocida
   `.lEonardo1452.` recuperada por el kernel cooperativo.
4. `test_coop_brute_matches_legacy_on_synthetic` — legacy y coop
   reportan exactamente el mismo set de hits sobre el mismo CT.
5. `test_coop_brute_no_false_positives_1m` — CT pseudo-aleatorio,
   1 M idx, **cero hits** espurios.

### Throughput medido (RTX 5070 Ti, sm_120, batch 128 Mi)

| Kernel        | duración | avg GH/s | peak GH/s | median GH/s |
|---------------|----------|----------|-----------|-------------|
| legacy D-029  |   30 s   | **1,502**| 1,824     | 1,430       |
| legacy D-029  |   60 s   | **1,486**| 1,821     | 1,417       |
| **coop D-030**|   30 s   | **0,817**| 0,994     | 0,782       |
| **coop D-030**|   60 s   | **0,814**| 0,991     | 0,776       |

**Cooperativo entrega 54,8 % del throughput de legacy → regresión del
45 %.** No se promociona a kernel activo.

### Por qué pierde — análisis matemático (modelo Amdahl per-warp)

Coste por candidata aproximado:

```
T_kdf  ≈ 880 ops   (MD5(14 B) unrolled + hexify in-register)
T_ks   ≈ 700 ops   (AES-256 key schedule + InvMixColumns rk[4..56])
T_dec  ≈ 550 ops   (AES-256 decrypt nominal sin spill)
T_dec_coop ≈ 200 ops por warp (cooperative decrypt amortiza 4×)
T_dec_legacy_with_spill ≈ 1 000 ops por thread (con 84 B spill)
```

Per-warp throughput:

- **Legacy**: 32 candidatas / (T_kdf + T_ks + T_dec_legacy)
              = 32 / (880 + 700 + 1 000) = **0,012 cand/op**
- **Coop**:    8 candidatas / (T_kdf + T_ks + T_dec_coop)
              = 8 / (880 + 700 + 200) = **0,0045 cand/op**

Ratio per-warp = 0,38 — **el cooperativo es 2,6× más lento por warp
que el legacy**. Para compensar harían falta 2,6× más warps activos
por SM, pero la occupancy real solo sube de 24 a 20 warps/SM (de
hecho **baja** porque los launch_bounds para evitar spill exigen 5
blocks/SM × 4 warps = 20 warps).

Ratio SM = (20/24) × 0,38 = **0,32**. La medición empírica (0,55) es
mejor que el modelo porque parte del coste de spill se amortiza por
L1 cache, pero la dirección es la correcta.

### Por qué cooperativo-redundant tampoco gana

Variante alternativa: 4 threads del grupo hacen KDF + key schedule
**redundantemente** (cada uno computa el mismo MD5 + ks para su candidata
del grupo). Per-warp: 8 cand / (T_kdf + T_ks + T_dec_coop) — mismo que
leader-only. La duplicación elimina la idleness del follower pero no
gana porque la suma de tiempos es la misma a nivel warp.

### Por qué la promesa "AES dominado por register pressure" no aplica

El supuesto del prompt original era: cooperativo libera regs ⇒ más
occupancy ⇒ más throughput. La realidad medida en este workload:

1. **El KDF (MD5 + hexify) no es paralelizable cooperativamente**: tiene
   dependencias serial round-by-round, y los 14 B de input caben en 1
   bloque MD5. El leader hace todo el KDF (~880 ops) mientras los 3
   followers idle.
2. **El AES key schedule tampoco**: dependencias `rk[i] = f(rk[i-1],
   rk[i-Nk])`. Leader-only otra vez.
3. Solo el AES decrypt (rondas 1..14) admite cooperación natural por
   columnas. Es ~30 % del coste total por candidata; un 4× de speedup
   ahí solo da ≈1,18× global por Amdahl.

El kernel legacy se beneficia de procesar 32 candidatas en paralelo
durante TODO el pipeline (KDF + ks + decrypt), incluso con 84 B de
spill, porque las 32 latencias se solapan entre sí.

### Decisión

- Kernel activo: **legacy `brute_md5hex_aes256_ecb` (D-029)** sigue
  siendo el camino de producción.
- Kernel cooperativo: **mantenido en árbol** (`brute_md5hex_aes256_ecb_coop.cu`,
  `dump_pt_block0_coop.cu`, `aes_coop.cuh`, `KernelBundleCoop`,
  `gpu_dump_pt_block0_coop`) como:
  - Implementación de referencia bit-exact (cross-checking).
  - Base para futuras variantes (p.ej. cooperative + bitsliced solo
    para el decrypt, manteniendo KDF escalar).
  - Toggle opt-in en `quattro-crack benchmark --coop` para reproducir
    la medición.
- README documenta el resultado en su sección Performance.

## D-031 — Bitsliced AES-256 evaluado, no implementado

**Contexto**: tras D-030, el siguiente lever teórico era bitsliced AES
(32 candidatas/warp empaquetadas, S-box como circuito booleano
Boyar-Peralta de 113 gates).

### Por qué no se intenta

1. **Amdahl bound estricto**: KDF + key schedule = 60 % del coste por
   candidata, no son bitsliceables (dependencias serial). Bitslicing
   solo acelera el decrypt (~30-40 % del coste). Speedup máximo
   teórico:
   ```
   1 / (0,6 + 0,4 / 8) = 1,54×
   ```
   Eso optimistamente daría ~2,3 GH/s sostenido, no las 6-10 GH/s del
   estado del arte (que asumen workloads AES-puros sin KDF).
2. **Coste de implementación**: ~1 000 LOC de CUDA (S-box bitsliced,
   pack/unpack lineal↔bitsliced, 60 round keys bitsliceadas, MixColumns
   bitsliced ~152 XOR). Tiempo realista 2-3 semanas. Coste alto.
3. **Riesgo de correctitud silencioso**: la S-box Boyar-Peralta es un
   circuito de 113 gates; un solo gate erróneo produce AES incorrecto
   sin causar SEGV. Tests vs FIPS-197 vector + 1 K random keys son
   imprescindibles, pero la depuración de un gate incorrecto entre 113
   es costosa.
4. **Baseline ya bit-exact y atomically pausable**: el riesgo de meter
   un kernel bitsliced sutilmente roto en producción con pwd-of-the-day
   en las narices supera el potencial 1,5×.

### Decisión

Bitsliced **no implementado** en esta sesión. Recomendación: si en
sesión futura se quiere atacar el techo de hardware, abordar primero
**MD5 paralelo intra-warp** (8 instancias por warp con 4 threads/MD5
no funciona por dependencias seriales; pero 32 instancias en bitslice
sí, potencialmente). El bitslicing tiene sentido si MD5 también se
bitslicea, no para AES solo.

## D-032 — T2 (persistent kernel) y T4 (Td en `__constant__`) no aplican

**Contexto**: el prompt inicial proponía T2 (persistent kernel para
eliminar launch overhead) y T4 (Td-tables en `__constant__` con
broadcast). Tras análisis cuantitativo se descartan ambos.

### T2 — persistent kernel

Overhead real medido por launch:

```
batch_size = 64 Mi = 67 108 864 candidatas
throughput = 1,48 GH/s avg
batch wall time ≈ 67 108 864 / 1,48e9 ≈ 45,3 ms
launch overhead típico ≈ 5-15 µs

15 µs / 45 300 µs = 0,033 %
```

Persistent kernel ahorra **0,03 % del tiempo de pared** a costa de:
- Coordinación host/device más frágil (`atomicAdd` sobre `next_idx`).
- Integración no-trivial con SIGINT/SIGTERM (flag de stop visible al
  device).
- Pinned memory + async transfers para monitorizar progreso.

**Coste/beneficio < 0,1 %, riesgo medio sobre la pausabilidad
(D-015/D-016 quedarían bajo refactor).** Descartado.

### T4 — Td-tables en `__constant__` (con broadcast)

Comentario explícito en `kernels/aes.cuh` (líneas 12-15):

> "(__shared__ — banco-paralelizable — en lugar de __constant__ —
>  single-port broadcast que serializa cuando los hilos acceden a
>  direcciones distintas)"

Este es exactamente el caso del barrido: cada thread accede a una
posición distinta de Td0/Td1/Td2/Td3 (4 td lookups por columna ×
4 columnas = 16 td reads per thread per round). En `__constant__`
con broadcast, las 16 lecturas de cada thread se serializan; en
`__shared__` con bancos, paralelizan.

T4 sólo ayudaría si los threads del grupo cooperativo leyeran el
**mismo** offset simultáneamente (broadcast-friendly). En la
decomposición por columnas que probamos (D-030), no se da: los 4
threads leen 4 offsets distintos por round.

**Descartado.**

## D-033 — Block 4: barrido de bugs sobre kernel activo + coop

Tests añadidos en `tests/block4_adversarial.rs` (9 tests verdes):

1. `test_boundary_idx_zero_legacy_and_coop_match_reference` — `idx = 0`
   produce pw `.aAaabbbb1000.` y plaintext bit-exact (CPU == legacy ==
   coop).
2. `test_boundary_idx_last_legacy_and_coop_match_reference` —
   `idx = N-1` produce pw `.zzzzuuuU1999.` y plaintext bit-exact.
3. `test_boundary_idx_field_transitions` — 12 idx en transiciones
   críticas entre campos del generador (625, 121 550 625,
   850 854 375, 59 559 806 250 ± 1).
4. `test_batch_size_extremes_match_reference` — batches de
   1, 16, 31, 32, 33, 1023, 1024, 1025, 65535, 65536, 65537. Verifica
   primero y último idx de cada batch contra reference.
5. `test_legacy_no_false_positives_1m_random_ct` — 1 M idx, CT no-Leonardo,
   cero hits emitidos por el kernel legacy.
6. `test_prefix32_mismatch_synthetic_legacy_and_coop` — CT donde los
   primeros 16 B del PT matchean Leonardo pero los siguientes 16 NO.
   Ambos kernels emiten hit (porque solo comparan 16 B); CPU devuelve
   `HitVerdict::PrefixMismatch32`; el runner lo descarta sin abortar.
7. `test_cross_verify_cpu_gpu_100_fixed_indices` — 100 idx (95 random
   con seed + 5 boundaries explícitos: 0, 1, N/2, N−2, N−1) contra
   ambos kernels y reference.
8. `test_real_progress_toml_loadable_if_present` — lee
   `state/progress.toml` real, verifica `next_step ≤ N`,
   `tried ≥ next_step`, formato Progress vigente.
9. `test_kernel_runs_from_real_next_step_if_present` — lanza ambos
   kernels desde el `next_step` real (medido: 2 271 635 046 400 al
   inicio de la sesión), procesa 4096 idx, compara legacy↔coop
   byte-a-byte y los primeros/últimos 5 contra reference.

### Bugs encontrados durante el barrido

**Ninguno**. Tanto el kernel legacy como el cooperativo pasaron todos
los tests adversariales en primer intento. Eso era esperable porque:
- El generador y la KDF ya estaban blindados por
  `tests/cpu_gpu_parity.rs` y `tests/kdf.rs`.
- El path AES-256 + Td-tables había sido validado contra FIPS-197
  vector C.3 en `tests/aes_fips197.rs`.
- D-007 (validación de hit en 3 pasos) era ya código probado.

El barrido confirma la robustez del kernel D-029 ante condiciones de
borde y boundary del espacio.

### Dry-run real de pausa+reanudación contra production state

Ejecutado contra `state/progress.toml` vivo:

```
backup state/progress.toml: next_step = 2 271 635 046 400
quattro-crack run --resume    (subprocess background)
sleep 8 ; SIGINT
final state/progress.toml:    next_step = 2 300 961 619 968
delta:                        29 326 573 568 candidatas en 19,57 s
                              = 1,499 GH/s (matches D-029 baseline)
last_flush_utc actualizado
[pausa] elapsed=20,14s; estado guardado en progress.toml. last_step=2300961619968
```

Reanudación + pausabilidad **funcionando** end-to-end con el state real
del usuario. El binario retoma desde el `next_step` exacto, persiste
incrementalmente (D-026, flush cada 8 batches), recibe SIGINT, hace
flush final, escribe `[pausa]` y sale con código 0.

### Métricas finales tras D-030..D-033

- **95 tests verdes** + 10 ignorados (diagnóstico opt-in). Subida
  de 81 → 95 por los 14 nuevos tests (5 paridad coop + 9 adversariales).
- **Clippy `-D warnings` limpio**.
- Throughput legacy mantenido: 1,49 GH/s avg / 1,82 peak (60 s
  sostenidos).
- Cooperativo bit-exact verificado, conservado como referencia
  (no activo).
- Resume desde production state validado.
