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

## D-012 — Throughput Fase 3: 1.2 GH/s sostenidos vs target 3 GH/s

**Estado medido** (RTX 5070 Ti, sm_120, `md5_utf8/cbc/zeros` AES-128,
batch 128 Mi, best-of-5):

```
≈ 1.2 GH/s sostenidos
```

El target preliminar de la spec era **≥ 3 GH/s**. Quedamos por debajo
por un factor 2.5×.

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
