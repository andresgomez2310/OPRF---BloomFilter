# 06: Construcción y publicación

**Responsable:** Roger Marenco Argote

**Peso:** 3

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** El Administrador, por línea de comandos y sin API pública, lee un corpus, aplica la regla canónica, evalúa cada contraseña sin cegado con la `skS` vigente e inserta las salidas en el filtro. Escribe el manifiesto y `bloom.bin`, firma el manifiesto y copia ambos al almacenamiento que el Servidor OPRF sirve en `/v1/filter/*`.

**Blocked by:** 01 Regla canónica, 02 Estructura del Bloom filter, 03 Evaluate y vectores RFC 9497

**Status:** ready-for-agent

- [ ] `build-filter` sobre 1, 1.000 y 100.000 contraseñas deja un manifiesto y un `bloom.bin` cuyo digest SHA-256 coincide con `bloombin_digest`.
- [ ] Cada contraseña del corpus pasa por la regla canónica y por `Evaluate` antes de insertarse.
- [ ] El manifiesto sigue el orden de claves, la suite y los parámetros `n`, `m`, `k` y `target_fpp` de la spec. La tasa objetivo por defecto es `0.01`.
- [ ] La firma Ed25519 cubre el manifiesto sin el campo `signature`, con la clave institucional, distinta de `skS`.
- [ ] `publish` deja esos artefactos donde `GET /v1/filter/manifest` y `GET /v1/filter/bloom` los leen.
- [ ] La herramienta no abre un puerto. El corpus no queda dentro del manifiesto ni del filtro en claro.
