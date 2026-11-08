# 09: Rotación de clave

**Responsable:** Daniel Cruzado Agudelo

**Peso:** 3

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** El Administrador rota la clave del servidor y la época juntas, reconstruye el filtro con la clave nueva y lo publica. El Servidor OPRF pasa a la época nueva y rechaza evaluaciones de la anterior. Un Cliente que todavía tiene el filtro viejo no responde con él: actualiza y solo entonces emite el veredicto contra el filtro nuevo. Una contraseña del corpus sigue saliendo `COMPROMETIDA` después de la rotación, y el filtro viejo deja de ser una fuente válida de ese veredicto.

**Blocked by:** 05 Servidor OPRF, 06 Construcción y publicación, 08 Caché e integridad

**Status:** ready-for-agent

- [ ] `rotate-key` genera otra `skS`, una época RFC 3339 distinta y un filtro nuevo evaluado con esa clave.
- [ ] `GET /v1/parameters` pasa a anunciar la época nueva cuando la rotación queda publicada.
- [ ] `POST /v1/oprf/evaluate` con la época anterior responde HTTP 400 y no evalúa.
- [ ] Un Cliente con caché de la época anterior actualiza manifiesto y filtro antes de dar un veredicto.
- [ ] Una contraseña del corpus obtiene `COMPROMETIDA` contra el filtro nuevo.
- [ ] Consultar la salida de la clave nueva sobre el filtro viejo no se acepta como veredicto. El Cliente no responde `COMPROMETIDA` a partir del filtro de la época anterior.
- [ ] La clave nueva queda en el fichero compartido por Administrador y Servidor OPRF. El Cliente sigue sin ella.
