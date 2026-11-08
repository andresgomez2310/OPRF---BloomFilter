# 11: Métricas

**Responsable:** Andres Gomez Rodriguez

**Peso:** 2

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Un comando mide el prototipo ya integrado y deja un informe con cuatro resultados: falsos positivos, latencia, tamaño y construcción del filtro, y rotación. Los números salen de ejecuciones reales del Cliente, el Servidor OPRF y el Administrador, y se pueden volver a generar.

**Blocked by:** 07 Veredicto COMPROMETIDA / NO ENCONTRADA, 08 Caché e integridad, 09 Rotación de clave

**Status:** ready-for-agent

- [ ] Al menos 10.000 consultas de contraseñas ausentes, generadas al azar, informan la tasa empírica de falsos positivos y la comparan con `p ≈ (1 − e^(−kn/m))^k` para las configuraciones de la tabla de referencia.
- [ ] El informe separa la latencia de una consulta con el filtro ya en caché y la de una consulta que tiene que descargarlo. El desglose cubre cegado, red, evaluación ciega, unblind y consulta del filtro.
- [ ] El informe da el tamaño de `bloom.bin` y el tiempo de `build-filter` para 50.000, 100.000 y 200.000 entradas.
- [ ] El informe da el tiempo entre `rotate-key` y el momento en que el filtro nuevo ya responde, y confirma que el filtro anterior no produce una coincidencia válida.
- [ ] Volver a lanzar el comando regenera el informe. Las entradas y la semilla usadas quedan escritas junto a los números.
