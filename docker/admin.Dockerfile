FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/admin ./cmd/admin

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/admin /usr/local/bin/admin
ENTRYPOINT ["sleep", "infinity"]