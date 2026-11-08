# 02: Estructura del Bloom filter

**Responsable:** Roger Marenco Argote

**Peso:** 3

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Dado un número de elementos y una tasa objetivo, el sistema calcula `m` y `k`, guarda un vector de bits y responde si un elemento de 64 bytes está insertado. Insertar y consultar usan las mismas posiciones. Un elemento insertado siempre se encuentra. El archivo binario se puede volver a leer y conserva los mismos bits.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] `(n=100000, p=0.01)` produce `m=958506` y `k=7`.
- [ ] `(n=100000, p=0.001)` produce `m=1437759` y `k=10`.
- [ ] `(n=1000000, p=0.01)` produce `m=9585058` y `k=7`.
- [ ] Las posiciones salen de la salida de 64 bytes como dice la spec: `h1` y `h2` big-endian de 8 bytes, `h2=1` si `h2` era 0, posición `i = (h1 + i·h2) mod m`.
- [ ] Todo elemento insertado se consulta como presente. El filtro no produce un falso negativo sobre lo que se insertó.
- [ ] El bit 0 del vector es el bit más significativo del byte 0. Si `m` no es múltiplo de 8, los bits sobrantes del último byte quedan en 0.
- [ ] Esta estructura se prueba con elementos de 64 bytes fijos. Todavía no depende de la salida OPRF ni del corpus.
