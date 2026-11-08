# 01: Regla canónica

**Responsable:** Andres Gomez Rodriguez

**Peso:** 2

**Spec:** `.scratch/verificacion-privada/spec.md`

**What to build:** Cliente y Administrador convierten una contraseña en los mismos bytes antes de cualquier evaluación: Unicode NFC y después UTF-8. Dos escrituras de la misma contraseña que solo se distinguen por la forma Unicode producen la misma entrada. Lo que la persona escribió se conserva: no se recorta ni se pasa a minúsculas.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] La misma contraseña produce siempre los mismos bytes.
- [ ] Una contraseña en NFC y su forma descompuesta (por ejemplo "café") producen los mismos bytes.
- [ ] Los espacios y las mayúsculas que vienen en la contraseña siguen presentes en los bytes.
- [ ] Cliente y Administrador usan esta misma función. Una prueba compartida lo demuestra con los mismos ejemplos en los dos lados.
- [ ] Los vectores crudos de RFC 9497 no pasan por esta función. La regla aplica solo a contraseñas.
