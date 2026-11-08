# 04: Cegado, unblind y finalize

**Responsable:** Darlen Arias Aleman

**Peso:** 5

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** El Cliente parte de los bytes de una contraseña, obtiene el punto en el grupo, lo ciega con un escalar nuevo, acepta un elemento evaluado y recupera la salida OPRF. Dos consultas de la misma contraseña salen hacia el servidor con elementos cegados distintos y terminan en la misma salida. Esa salida coincide con `Evaluate` del Administrador para la misma época. Un punto identidad, en la contraseña o en la respuesta, detiene el protocolo.

**Blocked by:** 03 Evaluate y vectores RFC 9497

**Status:** ready-for-agent

- [ ] Dos ejecuciones de la misma contraseña generan elementos cegados distintos.
- [ ] Esas dos ejecuciones producen la misma salida OPRF después de deshacer el cegado.
- [ ] Esa salida es igual, byte a byte, a `Evaluate(skS, input_bytes)` para la misma época.
- [ ] Si la contraseña cae en el elemento identidad, el Cliente aborta y no envía nada.
- [ ] Si el elemento evaluado no deserializa o es el elemento identidad, el Cliente aborta y no emite salida OPRF.
- [ ] El Cliente usa el módulo de primitivas del ticket 03. No reimplementa la suite ni inventa el hash de "Finalize".
