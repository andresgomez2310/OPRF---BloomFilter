# OPRF---BloomFilter
Sistema de verificación privada de contraseñas comprometidas utilizando OPRF y Bloom Filter, sin revelar información sensible al servidor.

## Componentes y versiones

| Componente     | Comando  | Directorio    | Ticket |
| -------------- | -------- | ------------- | ------ |
| Administrador  | `admin`  | `cmd/admin`   | 01–03, 06, 09 |
| Servidor OPRF  | `server` | `cmd/server`  | 05     |
| Cliente        | `client` | `cmd/client`  | 07     |

- Go: `1.27.4` (ver `go.mod`)
- `github.com/cloudflare/circl`: `v1.6.5`
- `suite_id`: `OPRF-ristretto255-SHA512`
- API: `/v1/parameters`, `/v1/oprf/evaluate`, `/v1/filter/manifest`, `/v1/filter/bloom`

## Docker Compose

```bash
# 1) Preparar directorios en el host
mkdir -p secrets data/filter data/corpus

# 2) Construir imágenes
docker compose build

# 3) Levantar servicios (el cliente queda inerte hasta el ticket 07)
docker compose up -d

# 4) Inicializar claves UNA sola vez
docker compose exec admin admin init-test-keys -dir /secrets

# 5) Corpus de ejemplo y publicación del filtro
echo -e "hunter2\npassword123" > data/corpus/demo.txt
docker compose exec admin admin build-filter \
    -corpus /data/corpus/demo.txt \
    -seed-file /secrets/oprf-seed.hex \
    -signing-seed-file /secrets/signing-seed.hex \
    -epoch 2026-Q1 \
    -out /tmp/filter-out \
    -publish-to /data/filter

# 6) Verificar parámetros
curl -s http://localhost:8080/v1/parameters | jq

# 7) Rotar la clave (nueva semilla y época, filtro nuevo)
docker compose exec admin admin rotate-key \
    -corpus /data/corpus/demo.txt \
    -seed-file /secrets/oprf-seed.hex \
    -signing-seed-file /secrets/signing-seed.hex \
    -out /tmp/filter-out \
    -publish-to /data/filter \
    -public-key-file /secrets/signing-public.hex

# 8) Comprobar que /v1/parameters anuncia la época nueva
curl -s http://localhost:8080/v1/parameters | jq