FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Creamos la carpeta de salida antes de intentar escribir en ella
RUN mkdir -p /out
# El cliente real vive en cmd/client (ticket 07). Mientras no exista,
# generamos un stub que explica el motivo.
RUN if [ -d ./cmd/client ]; then \
        CGO_ENABLED=0 go build -trimpath -o /out/client ./cmd/client; \
    else \
        printf '#!/bin/sh\necho "client: pendiente ticket 07" >&2\nexit 1\n' > /out/client && \
        chmod +x /out/client; \
    fi

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/client /usr/local/bin/client
ENTRYPOINT ["sleep", "infinity"]