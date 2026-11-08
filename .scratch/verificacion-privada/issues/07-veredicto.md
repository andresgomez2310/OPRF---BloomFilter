# 07: Veredicto COMPROMETIDA / NO ENCONTRADA

**Responsable:** Darlen Arias Aleman

**Peso:** 4

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Una persona escribe una contraseña en el Cliente. El Cliente completa el protocolo contra el Servidor OPRF, consulta el filtro publicado de la misma época y responde `COMPROMETIDA` o `NO ENCONTRADA EN LA LISTA`. Una contraseña del corpus sale comprometida. Una contraseña ausente del fixture sale no encontrada. El texto del veredicto negativo no dice que la contraseña sea segura.

**Blocked by:** 04 Cegado, unblind y finalize, 05 Servidor OPRF, 06 Construcción y publicación

**Status:** ready-for-agent

- [ ] Con un corpus fixture publicado, una contraseña que está en el corpus obtiene `COMPROMETIDA`.
- [ ] Una contraseña ausente, fijada de antemano para que sus `k` posiciones estén en cero en ese filtro, obtiene `NO ENCONTRADA EN LA LISTA`.
- [ ] El veredicto sale de la salida OPRF del Cliente sobre el `bloom.bin` de la misma época. Todas las posiciones en 1 significan `COMPROMETIDA`.
- [ ] El mensaje de ausencia dice que no está en la lista. No la califica como segura ni como fuerte.
- [ ] El Cliente no conoce `skS`. La prueba levanta el servidor con la clave y el cliente sin ella, y el veredicto igual coincide con lo que el Administrador insertó.
- [ ] Repetir la consulta de la contraseña presente vuelve a dar `COMPROMETIDA`, aunque el elemento cegado de cada consulta sea distinto.
