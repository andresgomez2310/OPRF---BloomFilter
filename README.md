# OPRF---BloomFilter

Sistema de verificación privada de contraseñas comprometidas utilizando OPRF y Bloom Filter, sin revelar la contraseña ni un hash ordinario al servidor.

La demostración corre en local con Docker Compose. No hace falta un despliegue público. Las pruebas automatizadas y las métricas corren en el host con Go.

## Requisitos

- [Docker Desktop](https://docs.docker.com/desktop/) en ejecución. En Windows, los comandos de abajo son para PowerShell.
- Git, para clonar el repositorio.
- [Go 1.27.4](https://go.dev/dl/) solo si vas a ejecutar `go test` o las métricas. La demostración con contenedores no lo necesita.

Comprueba las herramientas antes de seguir:

```powershell
docker version
git --version
go version
```

`go version` debe mostrar `go1.27.4`. Si solo vas a seguir la demostración, puedes omitir esa comprobación.

## Obtener el código

```powershell
git clone https://github.com/andresgomez2310/OPRF---BloomFilter.git
cd OPRF---BloomFilter
```

Si el repositorio ya está clonado, entra en esa carpeta y continúa desde ahí. `secrets/` y `data/` no se versionan.

## Versiones fijadas

| Componente    | Comando   | Directorio     |
| ------------- | --------- | -------------- |
| Administrador | `admin`   | `cmd/admin`    |
| Servidor OPRF | `server`  | `cmd/server`   |
| Cliente       | `cliente` | `cmd/cliente`  |

- **Go:** `1.27.4` (`go.mod` y las imágenes `golang:1.27.4-alpine`)
- **Librería OPRF:** `github.com/cloudflare/circl` `v1.6.5` (`go.mod` y `go.sum`)
- **Unicode NFC:** `golang.org/x/text` `v0.44.0`
- **Suite ID:** `OPRF-ristretto255-SHA512`
- **Firma del manifiesto:** Ed25519
- **Digest de `bloom.bin`:** SHA-256
- **API:** `GET /v1/parameters`, `POST /v1/oprf/evaluate`, `GET /v1/filter/manifest`, `GET /v1/filter/bloom`

La carpeta `secrets` completa se monta solo en `admin` y `servidor`. El cliente recibe únicamente `signing-public.hex`. No recibe `skS`, la semilla de firma ni el corpus.

## Demostración

El archivo `signing-public.hex` tiene que existir antes de `docker compose up`. Docker monta esa ruta como archivo. Si todavía no existe, la convierte en un directorio y el cliente no puede leer la clave.

### 1. Preparar directorios

```powershell
New-Item -ItemType Directory -Force -Path secrets, data\filter, data\corpus
```

### 2. Construir las imágenes

```powershell
docker compose build
```

### 3. Crear las claves de prueba, una sola vez

```powershell
docker compose run --rm --no-deps --entrypoint admin admin init-test-keys -dir /secrets
```

Si las claves ya existen, el comando se niega a sobrescribirlas. En ese caso pasa al paso siguiente.

### 4. Levantar los tres servicios

```powershell
docker compose up -d
```

### 5. Crear un corpus sintético y construir el filtro

Las dos contraseñas son de ejemplo. El archivo se escribe sin BOM para que la primera línea sea exactamente `hunter2`.

```powershell
[System.IO.File]::WriteAllText("$PWD\data\corpus\demo.txt", "hunter2`npassword123`n")

docker compose exec admin admin build-filter `
    -corpus /data/corpus/demo.txt `
    -seed-file /secrets/oprf-seed.hex `
    -signing-seed-file /secrets/signing-seed.hex `
    -epoch 2026-Q1 `
    -out /tmp/filter-out
```

### 6. Publicar el filtro

```powershell
docker compose exec admin admin publish `
    -from /tmp/filter-out `
    -to /data/filter `
    -public-key-file /secrets/signing-public.hex
```

### 7. Comprobar la época publicada

```powershell
curl.exe http://localhost:8080/v1/parameters
```

La respuesta incluye `"suite_id":"OPRF-ristretto255-SHA512"` y `"key_epoch":"2026-Q1"`.

### 8. Pedir un veredicto

```powershell
"hunter2" | docker compose exec -T cliente cliente
"no-esta-en-el-corpus" | docker compose exec -T cliente cliente
```

`hunter2` está en el corpus y responde `COMPROMETIDA`. `no-esta-en-el-corpus` responde `NO ENCONTRADA EN LA LISTA`. La contraseña se lee por stdin. El cliente envía solo el elemento cegado, descarga el filtro de la época anunciada y lo guarda en su caché.

### 9. Rotar la clave y volver a consultar

```powershell
docker compose exec admin admin rotate-key `
    -corpus /data/corpus/demo.txt `
    -seed-file /secrets/oprf-seed.hex `
    -signing-seed-file /secrets/signing-seed.hex `
    -out /tmp/filter-out `
    -publish-to /data/filter `
    -public-key-file /secrets/signing-public.hex

curl.exe http://localhost:8080/v1/parameters
"hunter2" | docker compose exec -T cliente cliente
```

`key_epoch` deja de ser `2026-Q1` y pasa a ser la hora UTC de la rotación. El servidor toma la semilla nueva sin reiniciarse. La consulta siguiente descarta el filtro cacheado, descarga el de la época nueva y vuelve a responder `COMPROMETIDA`.

Para parar los contenedores:

```powershell
docker compose down
```

## Pruebas automatizadas

Hacen falta Go `1.27.4` y el directorio del repositorio. No hace falta tener los contenedores en marcha: las pruebas levantan el servidor en el proceso de test.

```powershell
go test ./... -count=1
```

La batería incluye consultas presentes y ausentes, cegado fresco, vectores de RFC 9497, elementos mal formados, el elemento identidad, una época distinta, y manifiesto, firma o `bloom.bin` alterados. `build-filter` se comprueba con corpus de 3, 1.000 y 100.000 entradas.

## Métricas

También corren en el host, con datos sintéticos. La ejecución completa mide construcción (50.000, 100.000 y 200.000 entradas), falsos positivos (10.000 consultas ausentes por configuración), latencia con caché y sin caché, y rotación de clave. Puede tardar varios minutos.

```powershell
go run ./cmd/metrics
```

Escribe `metrics/report.md` y `metrics/results.json`. Para repetir solo una parte:

```powershell
go run ./cmd/metrics latency
go run ./cmd/metrics rotation
```
