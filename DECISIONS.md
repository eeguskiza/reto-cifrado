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
