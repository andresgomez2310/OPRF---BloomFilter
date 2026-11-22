# Ticket 11 - Métricas del prototipo OPRF + Bloom Filter

## Reproducibilidad

- Generado: `2026-11-22T21:58:33Z`
- Go: `go1.27.4`
- Plataforma: `windows/amd64`
- Semilla del generador de consultas ausentes: `20261121`
- Consultas ausentes por configuración: `10000`
- Muestras de latencia por modo: `30`
- Entradas usadas para rotación: `10000`
- Semilla OPRF de prueba: `1111111111111111111111111111111111111111111111111111111111111111`
- Semilla Ed25519 de prueba: `2222222222222222222222222222222222222222222222222222222222222222`

Las semillas anteriores son exclusivamente deterministas para las métricas locales del proyecto y no corresponden a claves de producción.

### Comandos

```bash
go run ./cmd/metrics
go run ./cmd/metrics latency
go run ./cmd/metrics rotation
go test ./... -count=1
```

## Construcción del Bloom Filter

| Entradas | Tiempo de build | bloom.bin | m bits | k |
|---:|---:|---:|---:|---:|
| 50000 | 4.0054742s | 59907 bytes | 479253 | 7 |
| 100000 | 5.2387119s | 119814 bytes | 958506 | 7 |
| 200000 | 10.3837471s | 239627 bytes | 1917012 | 7 |

## Falsos positivos

| n | FPP objetivo | m | k | Ausentes | Falsos positivos | FPP empírica | FPP teórica | Presentes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100000 | 0.010000 | 958506 | 7 | 10000 | 90 | 0.009000 | 0.010039 | 5/5 COMPROMETIDA |
| 100000 | 0.001000 | 1437759 | 10 | 10000 | 16 | 0.001600 | 0.001000 | 5/5 COMPROMETIDA |
| 1000000 | 0.010000 | 9585058 | 7 | 10000 | 109 | 0.010900 | 0.010039 | 5/5 COMPROMETIDA |

## Latencia

Los valores son promedios por consulta. `network` corresponde al tiempo HTTP descontando la evaluación OPRF del servidor para evitar contarla dos veces.

| Modo | Muestras | Total | Blind | Network | Evaluación | Unblind | Bloom lookup |
|---|---:|---:|---:|---:|---:|---:|---:|
| uncached | 30 | 53.429 ms | 0.138 ms | 46.318 ms | 0.098 ms | 0.146 ms | 0.095 µs |
| cached | 30 | 29.202 ms | 0.138 ms | 27.838 ms | 0.098 ms | 0.146 ms | 0.095 µs |

## Rotación de clave y filtro

- Tiempo hasta disponer del nuevo filtro: `1.4076208s`
- Época anterior: `metrics-rotation-old`
- Nueva época: `2026-11-22T21:58:31Z`
- Nuevo filtro disponible: `true`
- Filtro anterior rechazado para la nueva salida: `true`
- Veredicto con la nueva época: `COMPROMETIDA`
- Intentos hasta observar la nueva época: `24`

## Criterios de aceptación

- [x] Al menos 10.000 consultas aleatorias ausentes por configuración de referencia.
- [x] Comparación entre FPP empírica y FPP teórica.
- [x] Las contraseñas presentes comprobadas responden `COMPROMETIDA`.
- [x] Latencia separada entre filtro sin caché y con caché.
- [x] Desglose de blind, red, evaluación ciega, unblind y Bloom lookup.
- [x] Tamaño de `bloom.bin` y tiempo de construcción para 50k, 100k y 200k entradas.
- [x] Medición desde `rotate-key` hasta respuesta válida con el nuevo filtro.
- [x] Confirmación de que el filtro anterior no produce una coincidencia válida con la nueva salida.
- [x] Entradas y semillas de medición registradas.
- [x] Procedimiento reproducible mediante comandos del repositorio.
