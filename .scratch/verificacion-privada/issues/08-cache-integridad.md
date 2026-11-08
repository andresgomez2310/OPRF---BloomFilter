# 08: Caché e integridad

**Responsable:** Roger Marenco Argote

**Peso:** 3

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** El Cliente guarda el manifiesto y el filtro de la época vigente. Si `GET /v1/parameters` sigue en esa época, reutiliza `bloom.bin` y no lo vuelve a descargar. Si la época cambió, descarta la caché y baja la versión nueva antes de consultar. Si el digest no coincide o la firma institucional es inválida, no emite veredicto.

**Blocked by:** 05 Servidor OPRF, 06 Construcción y publicación

**Status:** ready-for-agent

- [ ] Con la misma época y el mismo ETag, una segunda consulta no vuelve a transferir `bloom.bin`.
- [ ] Cuando la época anunciada en `/v1/parameters` difiere de la caché, el Cliente descarga manifiesto y filtro nuevos antes de evaluar.
- [ ] Cambiar un byte de `bloom.bin` hace que el Cliente lo rechace por digest y no emita veredicto.
- [ ] Un manifiesto con firma inválida, o firmado por otra clave, se rechaza antes de usarse.
- [ ] El Cliente compara el SHA-256 real de `bloom.bin` con `bloombin_digest` y verifica Ed25519 con la clave pública institucional.
- [ ] La búsqueda no continúa sobre un filtro de otra época. Primero actualiza, después consulta.
