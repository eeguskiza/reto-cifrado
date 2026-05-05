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
