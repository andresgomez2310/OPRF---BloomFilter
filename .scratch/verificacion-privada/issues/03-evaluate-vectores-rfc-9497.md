# 03: Evaluate y vectores RFC 9497

**Responsable:** Andres Gomez Rodriguez

**Peso:** 5

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Existe un único módulo de primitivas, compartido por Administrador, Servidor OPRF y Cliente, que envuelve la suite `OPRF-ristretto255-SHA512` de circl. `Evaluate(skS, input_bytes)` devuelve la salida OPRF sin cegado. Los vectores oficiales del Apéndice A.1.1 de RFC 9497 coinciden byte a byte con lo que el módulo produce, incluidos el elemento cegado, el elemento evaluado y la salida.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] El módulo es el único que toca escalares, puntos de grupo y `skS`.
- [ ] Los vectores A.1.1 de `ristretto255-SHA512` coinciden byte a byte en semilla, clave derivada, entrada, blind, elemento cegado, elemento evaluado y salida.
- [ ] `Evaluate(skS, input_bytes)` devuelve esa misma salida OPRF para la entrada del vector, sin cegado.
- [ ] Los bytes de entrada del vector se usan tal cual. No pasan por la regla canónica.
- [ ] Cliente, Servidor OPRF y Administrador quedan obligados a llamar a este módulo. No añaden otra envoltura de circl.
