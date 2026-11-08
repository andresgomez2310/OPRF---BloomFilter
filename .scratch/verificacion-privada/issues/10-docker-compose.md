# 10: Docker Compose

**Responsable:** Daniel Cruzado Agudelo

**Peso:** 2

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Un `docker compose up` levanta tres servicios — `admin`, `servidor` y `cliente` — y con ellos se puede publicar un corpus pequeño y obtener el veredicto de una contraseña. La clave del servidor no viaja en la imagen ni en el volumen del Cliente. Go, circl y el `suite_id` quedan fijados y anotados en el README.

**Blocked by:** 05 Servidor OPRF, 06 Construcción y publicación, 07 Veredicto COMPROMETIDA / NO ENCONTRADA

**Status:** ready-for-agent

- [ ] `docker compose up` deja en ejecución `admin`, `servidor` y `cliente`, y un comando documentado recorre publicación y veredicto dentro de esa red.
- [ ] El volumen de `skS` está montado en `admin` y `servidor`. No está montado en `cliente`.
- [ ] La imagen del Cliente no contiene la clave del servidor ni el corpus.
- [ ] El README indica las versiones fijadas de Go y de circl, y el `suite_id` `OPRF-ristretto255-SHA512`.
- [ ] El mismo flujo de una contraseña presente y una ausente del fixture da los mismos veredictos que fuera de los contenedores.
