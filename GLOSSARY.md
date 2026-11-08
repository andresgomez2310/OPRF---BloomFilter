# Verificación privada de contraseñas

Servicio en el que una persona comprueba si una contraseña está en un corpus de contraseñas comprometidas, sin entregar esa contraseña al servidor.

## Language

**Contraseña**:
El secreto en texto plano que la persona quiere comprobar. Permanece en el Cliente.
_Avoid_: clave, password en claro hacia el servidor, hash de la contraseña

**Corpus**:
La lista de contraseñas comprometidas con la que el Administrador construye el filtro.
_Avoid_: base de datos de usuarios, diccionario en línea

**Regla canónica**:
La única codificación de una contraseña antes de evaluarla: Unicode NFC y después UTF-8.
_Avoid_: normalización libre, trim, minúsculas

**Cliente**:
Quien conserva la contraseña, habla con el Servidor OPRF y emite el veredicto.
_Avoid_: usuario, navegador, frontend

**Servidor OPRF**:
Quien custodia la clave del servidor, evalúa elementos cegados y entrega el filtro vigente.
_Avoid_: servidor de contraseñas, base de datos

**Administrador**:
La herramienta offline que construye el filtro, lo publica y rota la clave del servidor.
_Avoid_: panel, API pública, backoffice

**Clave del servidor**:
El secreto `skS` con el que el Servidor OPRF evalúa durante una época.
_Avoid_: contraseña, clave del usuario, clave de firma

**Época**:
El identificador `key_epoch` que ata una clave del servidor a un filtro publicado.
_Avoid_: versión del software, versión de la API

**Elemento cegado**:
El único valor derivado de la contraseña que el Cliente envía al Servidor OPRF.
_Avoid_: hash, contraseña cifrada, token

**Elemento evaluado**:
La respuesta del Servidor OPRF al elemento cegado. Todavía no es la salida OPRF.
_Avoid_: resultado, veredicto, hash final

**Salida OPRF**:
Los bytes finales de la evaluación. Los obtienen el Cliente y, sin cegado, el Administrador.
_Avoid_: hash ordinario, elemento evaluado, veredicto

**Filtro de Bloom**:
La estructura probabilística que guarda las salidas OPRF del corpus.
_Avoid_: lista de contraseñas, conjunto cifrado, caché

**Veredicto**:
La respuesta al usuario: `COMPROMETIDA` o `NO ENCONTRADA EN LA LISTA`.
_Avoid_: segura, insegura, coincidencia exacta

**Falso positivo**:
Un veredicto `COMPROMETIDA` para una contraseña que no está en el corpus.
_Avoid_: error del protocolo, falso negativo

**Manifiesto**:
Los metadatos firmados del filtro publicado: época, parámetros, digest y firma.
_Avoid_: bloom.bin, configuración del servidor
