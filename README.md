# OPRF---BloomFilter

Sistema de verificación privada de contraseñas comprometidas utilizando OPRF y Bloom Filter, sin revelar información sensible al servidor.

## Componentes y versiones

| Componente     | Comando  | Directorio    | Ticket |
| -------------- | -------- | ------------- | ------ |
| Administrador  | `admin`  | `cmd/admin`   | 01–03, 06, 09 |
| Servidor OPRF  | `server` | `cmd/server`  | 05     |
| Cliente        | `cliente` | `cmd/cliente` | 04, 07, 09 |

- **Go:** `1.27.4` (ver `go.mod`)
- **Librería:** `github.com/cloudflare/circl` `v1.6.5`
- **Suite ID:** `OPRF-ristretto255-SHA512`
- **API:** `/v1/parameters`, `/v1/oprf/evaluate`, `/v1/filter/manifest`, `/v1/filter/bloom`

## Docker Compose

Todos los comandos están adaptados para ejecutarse en **Windows PowerShell**. La carpeta `secrets` se monta solo en `admin` y `servidor`. La imagen y el volumen de `cliente` no reciben `skS` ni el corpus.

### 1. Preparar directorios en el host
```powershell
New-Item -ItemType Directory -Force -Path secrets, data\filter, data\corpus
```

### 2. Construir y levantar los servicios
```powershell
docker compose build
docker compose up -d
```

### 3. Inicializar claves (UNA sola vez)
```powershell
docker compose exec admin admin init-test-keys -dir /secrets
```

### 4. Crear corpus de ejemplo y construir el filtro
```powershell
Set-Content -Path data\corpus\demo.txt -Value "hunter2", "password123" -Encoding utf8

docker compose exec admin admin build-filter `
    -corpus /data/corpus/demo.txt `
    -seed-file /secrets/oprf-seed.hex `
    -signing-seed-file /secrets/signing-seed.hex `
    -epoch 2026-Q1 `
    -out /tmp/filter-out
```

### 5. Publicar el filtro para que el servidor lo lea
```powershell
docker compose exec admin admin publish `
    -from /tmp/filter-out `
    -to /data/filter `
    -public-key-file /secrets/signing-public.hex
```

### 6. Verificar los parámetros del servidor
```powershell
curl.exe http://localhost:8080/v1/parameters
```
*(Deberías ver `"key_epoch":"2026-Q1"` en la respuesta).*

### 7. Rotar la clave (nueva semilla, nueva época y filtro nuevo)
```powershell
docker compose exec admin admin rotate-key `
    -corpus /data/corpus/demo.txt `
    -seed-file /secrets/oprf-seed.hex `
    -signing-seed-file /secrets/signing-seed.hex `
    -out /tmp/filter-out `
    -publish-to /data/filter `
    -public-key-file /secrets/signing-public.hex
```

### 8. Comprobar la rotación en caliente
```powershell
curl.exe http://localhost:8080/v1/parameters
```
*(El `key_epoch` ya no será `2026-Q1`, sino la fecha exacta del momento de la rotación. El servidor se actualiza sin reiniciarse).*

### 9. Pedir un veredicto dentro de la red de Compose
```powershell
"hunter2" | docker compose exec -T cliente cliente
"no-esta-en-el-corpus" | docker compose exec -T cliente cliente
```
La primera contraseña está en el corpus y responde `COMPROMETIDA`. La segunda no está y responde `NO ENCONTRADA EN LA LISTA`. El cliente descarga el filtro de la época anunciada en `/v1/parameters` y lo guarda en su caché. Si `rotate-key` publica otra época, la siguiente consulta descarta ese filtro y baja el nuevo antes de responder.