# Verificación privada de contraseñas comprometidas

Spec del prototipo descrito en la Primera Entrega. El vocabulario es el de `GLOSSARY.md`.

## Problem Statement

Una contraseña que ya apareció en una filtración puede reutilizarse contra este u otro sistema. Comprobarla enviándola al servidor, o enviando un hash ordinario, revela el secreto que la persona intenta proteger. El servidor no debe enterarse de la contraseña ni de la salida final de la comprobación.

## Solution

El Cliente y el Servidor OPRF calculan juntos una salida OPRF en modo básico (RFC 9497, suite `OPRF-ristretto255-SHA512`). El Cliente envía solo un elemento cegado nuevo en cada consulta. La salida OPRF la obtiene el Cliente. El Administrador, offline y sin cegado, evalúa el corpus con la misma clave del servidor y publica un filtro de Bloom. El Cliente consulta ese filtro en local y responde `COMPROMETIDA` o `NO ENCONTRADA EN LA LISTA`.

Una coincidencia puede ser un falso positivo. Una ausencia solo dice que la contraseña no está en este corpus. El filtro no produce falsos negativos si se construyó y se consultó con la misma época, la misma regla canónica y la misma salida OPRF.

## User Stories

1. Como persona que va a elegir una contraseña, quiero escribirla en el Cliente y recibir un veredicto, para saber si está en el corpus publicado.
2. Como persona, quiero que el Servidor OPRF no reciba mi contraseña, para que una consulta no le entregue el secreto.
3. Como persona, quiero que el Servidor OPRF no reciba un hash ordinario de mi contraseña, para que no pueda comparar la consulta con un diccionario precalculado.
4. Como persona, quiero que dos consultas de la misma contraseña envíen elementos cegados distintos, para que el servidor no relacione esas consultas entre sí.
5. Como persona, quiero que esas dos consultas produzcan la misma salida OPRF y el mismo veredicto, para que el cegado fresco no cambie el resultado.
6. Como persona, quiero que una contraseña que sí está en el corpus reciba `COMPROMETIDA`, para que el sistema no me diga que está limpia.
7. Como persona, quiero que una contraseña ausente del corpus reciba `NO ENCONTRADA EN LA LISTA` cuando las posiciones del filtro están en cero, para distinguir ausencia de coincidencia.
8. Como persona, quiero que `NO ENCONTRADA EN LA LISTA` signifique solo ausencia en este corpus, para no confundirlo con "contraseña segura".
9. Como persona, quiero que `COMPROMETIDA` se entienda como coincidencia probable, para tener presente el falso positivo.
10. Como persona, quiero que el Cliente rechace un elemento evaluado mal formado antes de calcular la salida OPRF, para no aceptar una respuesta corrupta.
11. Como persona, quiero que el Cliente aborte si la contraseña cae en el elemento identidad, para no continuar un caso degenerado.
12. Como persona, quiero que el Cliente aborte si el Servidor OPRF devuelve el elemento identidad, para no deshacer el cegado sobre un punto inválido.
13. Como persona, quiero que el Cliente actualice el filtro cuando la época del servidor no coincide con la de su caché, para no consultar un filtro de otra clave.
14. Como persona, quiero que el Cliente reutilice el filtro cacheado cuando la época y el ETag siguen vigentes, para no descargarlo en cada consulta.
15. Como persona, quiero que el Cliente se niegue a usar un `bloom.bin` cuyo digest no coincide con el manifiesto, para no aceptar un filtro alterado.
16. Como persona, quiero que el Cliente se niegue a usar un manifiesto con firma inválida, para no aceptar un filtro plantado.
17. Como Administrador, quiero importar un corpus y construir el filtro con la clave del servidor vigente, para publicar exactamente las salidas que el Cliente va a calcular.
18. Como Administrador, quiero que la herramienta aplique la misma regla canónica que el Cliente, para que una misma contraseña no produzca dos salidas.
19. Como Administrador, quiero un manifiesto y un `bloom.bin` coherentes entre sí, para que el Cliente pueda interpretar los bits.
20. Como Administrador, quiero publicar esos artefactos en el almacenamiento que sirve el Servidor OPRF, para que el Cliente los descargue.
21. Como Administrador, quiero rotar la clave del servidor y la época juntas y publicar un filtro nuevo, para que el filtro viejo deje de ser consultable.
22. Como Administrador, quiero operar por línea de comandos, sin API pública, para que el corpus y la rotación no queden expuestos en la red.
23. Como Servidor OPRF, quiero anunciar la suite, la época vigente y la versión de API, para que el Cliente detecte un desajuste antes de evaluar.
24. Como Servidor OPRF, quiero evaluar un elemento cegado de la época vigente y devolver solo el elemento evaluado, para no ver la contraseña ni la salida OPRF.
25. Como Servidor OPRF, quiero rechazar un elemento que no deserializa y el elemento identidad, para no evaluarlo.
26. Como Servidor OPRF, quiero rechazar un elemento cegado presentado con otra época, para no mezclar claves.
27. Como Servidor OPRF, quiero que la evaluación no ramifique según la clave del servidor, para que el tiempo de respuesta no filtre `skS`.
28. Como Servidor OPRF, quiero servir el manifiesto con ETag y el filtro como bytes, para que el Cliente aplique su caché.
29. Como Servidor OPRF, quiero no almacenar contraseñas, elementos cegados ni sesiones, para que un registro del servicio no sea un historial de consultas.
30. Como integrante del equipo, quiero reproducir byte a byte los vectores del Apéndice A.1.1 de RFC 9497 para `ristretto255-SHA512`, para saber que la suite integrada es la del RFC.
31. Como integrante del equipo, quiero una sola biblioteca de primitivas compartida por Administrador, Servidor OPRF y Cliente, para que las tres partes no diverjan.
32. Como integrante del equipo, quiero levantar Administrador, Servidor OPRF y Cliente con Docker Compose, para repetir el demo en local.
33. Como integrante del equipo, quiero que la imagen del Cliente no contenga la clave del servidor, para conservar la separación de secretos.
34. Como evaluador, quiero la tasa empírica de falsos positivos sobre al menos 10.000 contraseñas ausentes, comparada con la predicción teórica, para justificar el tamaño del filtro.
35. Como evaluador, quiero la latencia de una consulta con filtro en caché y sin él, para ver el efecto de la caché.
36. Como evaluador, quiero el tamaño de `bloom.bin` y el tiempo de construcción para 50.000, 100.000 y 200.000 entradas, para conocer el costo del corpus.
37. Como evaluador, quiero el tiempo desde una rotación hasta que el filtro nuevo se puede consultar, y la confirmación de que el filtro anterior ya no produce una coincidencia válida, para cerrar el protocolo de época.
38. Como persona, quiero que "café" en NFC y la misma palabra en forma descompuesta produzcan la misma salida OPRF, para que la regla canónica una las dos escrituras.
39. Como persona, quiero que los espacios que escribí se conserven, para que la regla canónica no invente otra contraseña recortando o pasando a minúsculas.
40. Como integrante del equipo, quiero que la interfaz (CLI y HTTP) no tome decisiones criptográficas, para que toda la suite viva en un solo módulo.

## Implementation Decisions

- Tres componentes, un lenguaje. Administrador, Servidor OPRF y Cliente se escriben en Go y comparten `cloudflare/circl` para la suite `OPRF-ristretto255-SHA512`. La aritmética de grupo no se reimplementa. La descripción del entregable `Hash(input_bytes || unblinded_bytes || "Finalize")` es el modelo conceptual; los bytes reales son los de RFC 9497 a través de circl. El contrato de bytes son los vectores del Apéndice A.1.1.
- Un solo módulo de primitivas. Es el único que toca escalares, puntos y `skS`. Lo abre el ticket 03. El Cliente, el Servidor OPRF y el Administrador lo llaman; no envuelven circl por su cuenta. La capa de interfaz no contiene lógica criptográfica.
- Modo OPRF básico. Sin VOPRF ni POPRF. `Evaluate(skS, input_bytes)` es la evaluación sin cegado que usa el Administrador. La salida de esa evaluación es la misma salida OPRF que el Cliente obtiene tras cegar, evaluar en el servidor y deshacer el cegado, para la misma época.
- Regla canónica compartida. `input_bytes` es Unicode NFC seguido de UTF-8. No hay recorte, no hay casefold y no se descartan espacios. Cliente y Administrador usan la misma función. Los vectores del RFC entran como bytes crudos del apéndice y no pasan por la regla canónica: la regla aplica solo a contraseñas.
- Elemento identidad. Si `hashToGroup` devuelve el elemento identidad, el Cliente aborta. El Servidor OPRF rechaza un elemento cegado que no deserializa o que es el elemento identidad, y no lo evalúa. El Cliente también rechaza un elemento evaluado que no deserializa o que es el elemento identidad.
- Cegado fresco. Cada consulta del Cliente genera un escalar aleatorio nuevo. Dos consultas de la misma contraseña producen elementos cegados distintos y la misma salida OPRF.
- Tiempo constante respecto de `skS`. El código propio del Servidor OPRF no introduce ramas ni retornos anticipados que dependan de la clave. La multiplicación es la de la biblioteca.
- API bajo `/v1`, sin autenticación. La construcción del filtro no se expone por red.
  - `GET /v1/parameters` → `{ "suite_id": "OPRF-ristretto255-SHA512", "key_epoch": "<string>", "api_version": "v1" }`.
  - `POST /v1/oprf/evaluate` recibe `{ "blindedElement": "<hex>", "key_epoch": "<string>" }` y responde `{ "evaluatedElement": "<hex>" }`. `blindedElement` y `evaluatedElement` son hex minúscula del elemento comprimido (32 bytes, `Ne = 32`). Época distinta de la vigente, elemento ilegible o elemento identidad: rechazo HTTP 400, sin evaluar y sin escribir el elemento en un registro.
  - `GET /v1/filter/manifest` devuelve el manifiesto y un ETag fuerte (SHA-256 hex del cuerpo, entre comillas).
  - `GET /v1/filter/bloom` devuelve `bloom.bin` como cuerpo binario.
- El Cliente, antes de evaluar, llama a `GET /v1/parameters`. Si `key_epoch` no coincide con el manifiesto cacheado, descarta la caché, descarga manifiesto y filtro, y solo entonces continúa. Si coinciden, reutiliza `bloom.bin`. El ETag evita volver a bajar un manifiesto que no cambió.
- Filtro de Bloom. Para `n` elementos y tasa objetivo `p`:
  - `m = round(-n · ln(p) / (ln 2)²)`
  - `k = round((m / n) · ln 2)`
  - Tasa teórica `p ≈ (1 − e^(−kn/m))^k`
  - Tabla de referencia que los tests deben reproducir: `(n=100000, p=0.01) → m=958506, k=7`; `(n=100000, p=0.001) → m=1437759, k=10`; `(n=1000000, p=0.01) → m=9585058, k=7`.
  - Tasa objetivo por defecto al construir: `0.01`.
  - Inserción y consulta comparten las posiciones. De la salida OPRF (64 bytes) se toman `h1` como los primeros 8 bytes big-endian y `h2` como los 8 siguientes. Si `h2` es 0, se usa 1. La posición `i` (desde 0 hasta `k-1`) es `(h1 + i·h2) mod m`.
  - `bloom.bin` es el vector de `m` bits. El bit 0 es el bit más significativo del byte 0. Si `m` no es múltiplo de 8, los bits sobrantes del último byte son 0.
- Manifiesto. JSON UTF-8 con las claves en este orden y sin firma dentro del documento que se firma:

```json
{
  "version": "1.0.0",
  "key_epoch": "2026-11-08T22:00:00Z",
  "suite_id": "OPRF-ristretto255-SHA512",
  "created_at": "2026-11-08T22:00:00Z",
  "parameters": {
    "n_elements": 100000,
    "m_bits": 958506,
    "k_hashes": 7,
    "target_fpp": 0.01
  },
  "hash_algorithm": "SHA-256",
  "bloombin_digest": "<sha256 hex de bloom.bin>"
}
```

  `bloombin_digest` es SHA-256 de los bytes exactos de `bloom.bin`. `key_epoch` es un string opaco comparado por igualdad. `rotate-key` le asigna la hora UTC de la rotación en RFC 3339. El ejemplo `2026-Q1-v1` del entregable es ilustrativo; el prototipo usa RFC 3339.

- Firma. Ed25519 sobre los bytes canónicos del manifiesto (claves en el orden de arriba, sin espacios de más, campo `signature` ausente). La firma viaja junto al manifiesto, en un campo `signature` hex, y no entra en los bytes firmados. La clave de firma es la clave institucional del servicio: es distinta de `skS`. La privada solo la tiene el Administrador. La pública va con el Cliente. Un digest distinto o una firma inválida impide el veredicto.
- Equivalencia. Para la misma época y los mismos `input_bytes`, la salida OPRF del Cliente es igual a `Evaluate(skS, input_bytes)` del Administrador. Por eso el filtro, construido con evaluaciones sin cegado, responde a la salida que el Cliente calcula con cegado.
- Rotación. Cambiar `skS` invalida todas las salidas anteriores. `rotate-key` genera otra `skS`, otra época, reconstruye el filtro y lo publica. El Servidor OPRF deja de aceptar evaluaciones de la época anterior. El Cliente, al ver épocas distintas, aborta la búsqueda, actualiza el filtro y solo entonces consulta. Un filtro de la época anterior no se usa para emitir `COMPROMETIDA`.
- Persistencia. `skS` vive en un fichero montado solo en Administrador y Servidor OPRF, o en una variable de entorno para las pruebas locales. No se commitea y no entra en la imagen del Cliente. El Servidor OPRF no guarda contraseñas, elementos cegados ni sesiones. El corpus y los artefactos publicados viven en el sistema de archivos local.
- Comandos del Administrador, sin red: `build-filter` (corpus → manifiesto + `bloom.bin`), `rotate-key` (nueva `skS` y nueva época, y filtro nuevo), `publish` (copia los artefactos al almacenamiento de `/v1/filter/*`).
- Docker Compose con tres servicios: `admin`, `servidor`, `cliente`. Las versiones de Go, de circl y el `suite_id` quedan fijadas y escritas en el README. El volumen de la clave no se monta en `cliente`.
- Veredicto. El Cliente calcula las `k` posiciones de su salida OPRF. Si todas están en 1, responde `COMPROMETIDA`. Si falta alguna, responde `NO ENCONTRADA EN LA LISTA`.

## Testing Decisions

Un buen test observa comportamiento externo: bytes de la regla canónica, bytes de los vectores RFC, respuestas HTTP, ficheros publicados, veredicto del Cliente y el informe de métricas. No afirma detalles internos de la aritmética de circl.

La costura más alta, y la única de primitivas, es el módulo que abre el ticket 03. Cliente, Servidor OPRF y Administrador se prueban contra esa costura y contra sus bordes visibles (CLI y HTTP). No aparece una segunda envoltura de la suite.

No hay tests previos en el repositorio. La referencia criptográfica son los vectores oficiales. La referencia del filtro es la tabla de `m` y `k` de esta spec. El veredicto negativo usa un fixture fijo (corpus y contraseña ausente ya comprobada), de modo que un falso positivo aleatorio no vuelva el test intermitente.

Cubren, en el ticket que los hace demostrables:

- Funcional: ciclo completo con una contraseña presente y una ausente; caché que reutiliza o vuelve a descargar; `build-filter` sobre 1, 1.000 y 100.000 contraseñas con manifiesto y `bloom.bin` coherentes.
- Criptográfico: cegado fresco, consistencia de la salida, equivalencia Cliente–Administrador, vectores A.1.1 byte a byte.
- Negativo: elemento ilegible, elemento identidad, época distinta, manifiesto o filtro alterado.
- Experimental: el ticket 11.

## Out of Scope

- VOPRF, POPRF y más de un servidor.
- Anonimato de red, ocultar IP, horario o frecuencia de consultas.
- Proteger al Cliente o al Servidor OPRF si el atacante ya controla su memoria, su clave o el binario.
- Juzgar la fortaleza de una contraseña más allá de la pertenencia al corpus.
- Una API pública para construir el filtro o para leer el corpus.
- Un segundo criptosistema para cifrar `skS` en disco. El aislamiento es el fichero o la variable de entorno, fuera del Cliente y fuera del repositorio. El modelo de adversario ya deja fuera el compromiso total del servidor.
- Interfaz web. El Cliente de este prototipo es CLI. La spec del entregable la menciona como opción; no entra en estos tickets.

## Further Notes

Reparto del curso. Cada persona suma peso 9. El número del ticket es el número del archivo.

| Ticket | Responsable | Peso | Bloqueado por |
| --- | --- | --- | --- |
| 01 Regla canónica | Andres Gomez Rodriguez | 2 | Ninguno |
| 02 Estructura del Bloom filter | Roger Marenco Argote | 3 | Ninguno |
| 03 Evaluate y vectores RFC 9497 | Andres Gomez Rodriguez | 5 | Ninguno |
| 04 Cegado, unblind y finalize | Darlen Arias Aleman | 5 | 03 |
| 05 Servidor OPRF | Daniel Cruzado Agudelo | 4 | 03 |
| 06 Construcción y publicación | Roger Marenco Argote | 3 | 01, 02, 03 |
| 07 Veredicto COMPROMETIDA / NO ENCONTRADA | Darlen Arias Aleman | 4 | 04, 05, 06 |
| 08 Caché e integridad | Roger Marenco Argote | 3 | 05, 06 |
| 09 Rotación de clave | Daniel Cruzado Agudelo | 3 | 05, 06, 08 |
| 10 Docker Compose | Daniel Cruzado Agudelo | 2 | 05, 06, 07 |
| 11 Métricas | Andres Gomez Rodriguez | 2 | 07, 08, 09 |

Pueden empezar a la vez Andres (01 y 03) y Roger (02). Darlen y Daniel entran cuando 03 está listo: Darlen en 04, Daniel en 05. Roger encadena 02 → 06 → 08. Darlen cierra con 07. Daniel hace 09 después de 08, y 10 cuando ya existen servidor, filtro y veredicto. Andres cierra con 11, cuando el flujo, la caché y la rotación ya se pueden medir.

La costura de pruebas quedó fijada por el entregable: un módulo de primitivas y tres componentes detrás de CLI y HTTP. No hace falta otra.
