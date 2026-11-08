# 05: Servidor OPRF

**Responsable:** Daniel Cruzado Agudelo

**Peso:** 4

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** El Servidor OPRF anuncia la suite, la época vigente y la versión de API, evalúa un elemento cegado de esa época y devuelve solo el elemento evaluado. Rechaza un elemento ilegible, el elemento identidad y una época que no es la vigente. Sirve el manifiesto con ETag y el filtro en bytes desde el almacenamiento publicado. No guarda contraseñas, elementos cegados ni sesiones.

**Blocked by:** 03 Evaluate y vectores RFC 9497

**Status:** ready-for-agent

- [ ] `GET /v1/parameters` responde `suite_id` `OPRF-ristretto255-SHA512`, el `key_epoch` vigente y `api_version` `v1`, sin autenticación.
- [ ] `POST /v1/oprf/evaluate` acepta `blindedElement` en hex minúscula de 32 bytes más `key_epoch`, y responde `evaluatedElement` en el mismo hex.
- [ ] Un elemento que no deserializa, el elemento identidad o una época distinta reciben HTTP 400 y no se evalúan.
- [ ] El código propio del servidor no ramifica según `skS`. La multiplicación sale del módulo de primitivas.
- [ ] `GET /v1/filter/manifest` entrega el manifiesto publicado y un ETag fuerte. `GET /v1/filter/bloom` entrega los bytes de `bloom.bin`.
- [ ] Tras una evaluación, el servidor no conserva el elemento cegado ni la contraseña. Una prueba recorre el estado persistido y no los encuentra.
- [ ] `skS` se carga desde el fichero de la spec o desde la variable de entorno de pruebas. No está en el código fuente.
