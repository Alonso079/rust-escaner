# shodan-pipeline

Pipeline asíncrono en Rust para recolectar hosts vía Shodan y escanearlos con RustScan + Nmap, aplicando reglas dinámicas y exportando resultados (CSV / JSON / Markdown). Incluye modos "hunt" y adaptativo para detenerse cuando se alcanza un número de hosts interesantes.

> Proyecto orientado a OSINT / enumeración controlada. Usa siempre tus propias claves y respeta los Términos de Uso de los servicios. **NO** está diseñado para uso malicioso.

---
## Índice
1. Visión General
2. Flujo de Ejecución
3. Módulos (arquitectura interna)
4. CLI y Subcomandos
5. Modos Especiales (Hunt / Adaptativo / Matriz de Puertos)
6. Variables de Entorno Soportadas
7. Formatos de Salida y Archivos Generados
8. Reglas Dinámicas (`rules.yaml`)
9. Reanudación (`--resume`) y Confirmación de `tcpwrapped`
10. Filtros de Puertos (`--hide-tcpwrapped`, `--only-open`)
11. Manejo de Dorks (keywords → Shodan)
12. Ejemplos de Uso
13. Errores Comunes y Consejos
14. Roadmap / Ideas Futuras

---
## 1. Visión General
El binario `shodan-pipeline` implementa una cadena:

```
Keywords -> Dork Shodan -> Colecta IPs -> (Opcional) RustScan descubrimiento rápido -> Nmap (profundiza) -> Filtros -> Reglas dinámicas -> Reportes
```

Dos estrategias clave:
- **Hunt**: escaneo por lotes pequeños hasta reunir un número de hosts "interesantes" (con varios puertos abiertos).
- **Adaptativo**: se escanean todas las IPs reunidas, ampliando el set si no se alcanza cierto número de hosts con umbral mínimo de puertos abiertos.

---
## 2. Flujo de Ejecución
1. Construcción de dork a partir de `--keywords` (normalización y expansión semántica limitada).
2. Pre‑check `/count` (para detectar dorks inválidos; fallback a `country:CL` si falla).
3. Recolección paginada Shodan (`/shodan/host/search`). Guarda `out/ips.txt`.
4. (Modo normal) Descubrimiento rápido de puertos por IP con RustScan → genera mapa IP → puertos.
5. Nmap sobre cada host (opcionalmente limitado a la lista de RustScan o fijo con `--fixed-ports`). Salva XML en `out/<ip>/nmap.xml`.
6. Parseo XML → estructura interna (`HostReport`).
7. Filtros (`--hide-tcpwrapped`, `--only-open`).
8. Reglas dinámicas: ejecución de comandos personalizados por puerto/servicio (`rules.yaml`). Logs en `out/<ip>/<rule>_<port>.log`.
9. Export: `report.csv`, `report.json`, `report.md`. Si Hunt: también archivos de hosts interesantes.
10. (Opcional) Confirmación de puertos `tcpwrapped` con re‑escaneo focalizado (`--confirm-wrapped`).

---
## 3. Módulos
| Módulo | Archivo | Rol Principal |
|--------|---------|---------------|
| args | `src/args.rs` | Definición CLI con `clap` (subcomandos y flags). |
| rules | `src/rules.rs` | Carga YAML de reglas (`Rules` / `Rule`). |
| models | `src/models.rs` | Estructuras de datos: `IpPorts`, `PortDetail`, `HostReport`. |
| shodan | `src/shodan.rs` | Construcción de dorks, cliente HTTP, recolección y deduplicación de IPs. |
| targets | `src/targets.rs` | Lectura de archivo de objetivos y resolución DNS asíncrona. |
| rustscan | `src/rustscan.rs` | Ejecución concurrente de RustScan, parseo `--greppable`. |
| nmap | `src/nmap.rs` | Normalización flags, ejecución concurrente, parseo XML, fallback SYN→Connect, confirmación `tcpwrapped`. |
| dynamic | `src/dynamic.rs` | Motor de reglas dinámicas: substituye placeholders y ejecuta comandos. |
| output | `src/output.rs` | Resúmenes, filtrado, export CSV/JSON/Markdown, helpers interés. |
| config | `src/config.rs` | Persistencia de API key en directorio de configuración del usuario. |
| lib | `src/lib.rs` | Re‑exporta módulos (biblioteca interna). |
| main | `src/main.rs` | Orquesta el pipeline según subcomando. |

### Relación Entre Componentes
```
main -> args
main -> (shodan) -> output/ips.txt
main -> (rustscan?) -> IpPorts -> nmap
nmap -> parse XML -> HostReport -> output / dynamic
rules + dynamic -> logs por host
```

---
## 4. CLI y Subcomandos
Subcomando principal: `full` (alias conceptual del pipeline completo).

### `full`
Parámetros clave:
- `--keywords <csv>`: Ej. `chile,.cl,muni`
- `--limit <N>`: Máximo IPs a recolectar (default 5).
- `--pages <N>`: Páginas Shodan a iterar (default 20, hard cap 100 en código).
- `--targets <file>`: Archivo extra de objetivos (IPs o dominios). Se agregan tras resolver DNS.
- `--fixed-ports <lista>`: Omite RustScan y fuerza una matriz de puertos (ej. `22,80,443,8000-8100`).
- `--rs-concurrency`, `--nmap-concurrency`: Concurrencias separadas.
- `--nmap-extra <flags>`: Flags base Nmap (sanitizadas internamente; se ajustan según privilegios). Default no root: `-sT -sV -Pn --version-intensity 5 --max-retries 2`.
- `--resume`: No re‑ejecuta Nmap si existe `out/<ip>/nmap.xml`.
- Filtros:
  - `--hide-tcpwrapped` (default true)
  - `--only-open` (default true)
  - `--confirm-wrapped` (reanálisis focalizado)
- Hunt:
  - `--hunt` activa modo iterativo por lotes
  - `--hunt-needed <N>` hosts interesantes deseados
  - `--hunt-min-open <N>` puertos abiertos mínimos para marcar interés
  - `--hunt-batch <N>` tamaño de cada lote de IPs
- Adaptativo (sin `--hunt`):
  - `--interesting-target <N>` objetivo de hosts interesantes
  - `--interesting-min-open <N>` umbral de puertos abiertos

### `intel`
Solo construye dork y recolecta IPs (crea `out/ips.txt`).

### `rustscan`
Ejecuta RustScan sobre un archivo de objetivos y produce `<input>.rustscan.jsonl`.

### `nmap`
Ejecuta Nmap a partir de un JSONL (`--input-jsonl`) con objetos `{ip, ports:[...]}` o usando `--fixed-ports`.

### `config`
Gestiona la API key persistente:
- `config --set <KEY>`
- `config --show-path`

### `clean`
Elimina `out/` y opcionalmente `target/` con `--deep`.

---
## 5. Modos Especiales
### Hunt (`--hunt`)
Escanea bloques sucesivos de `--hunt-batch` IPs hasta reunir `--hunt-needed` hosts que cumplan `--hunt-min-open` puertos abiertos (tras filtros). Genera además archivos `report_interesting.*`.

### Adaptativo (`--interesting-target > 0`)
Escanea todas las IPs (en tandas). Si no alcanza `interesting_target` y todavía hay margen (no alcanzó `--limit`), intenta ampliar el set agregando páginas extra (ventana pequeña). Se detiene al cumplirse el objetivo o alcanzar límite.

### Matriz de Puertos (`--fixed-ports`)
Ignora descubrimiento y fuerza un set estático.

---
## 6. Variables de Entorno
| Variable | Efecto |
|----------|--------|
| `SHODAN_API_KEY` | API key si no se pasa `--key` ni existe config persistente. |
| `RUST_SHODAN_HUNT_NMAP_ONLY` | Si se define a `1/true`, omite RustScan durante Hunt (Nmap usa sus puertos por defecto). |
| `RUST_SHODAN_ADAPTIVE_NMAP_ONLY` | Igual que anterior pero en modo adaptativo. |

---
## 7. Formatos de Salida
| Archivo | Contenido |
|---------|-----------|
| `out/ips.txt` | Lista de IPs únicas recolectadas. |
| `out/<ip>/nmap.xml` | Salida XML Nmap individual. |
| `out/<ip>/nmap.stderr.txt` | Stderr de Nmap si hubo fallo. |
| `out/<ip>/<rule>_<port>.log` | Log de comando dinámico ejecutado. |
| `out/rustscan.jsonl` | (modo adaptativo) Append incremental de descubrimientos RustScan. |
| `out/report.csv` | Host, IP, puerto, estado, servicio (filtrados). |
| `out/report.json` | Lista JSON de hosts con puertos. |
| `out/report.md` | Versión Markdown (solo en Hunt actualmente). |
| `out/report_interesting.*` | Archivos análogos pero solo hosts interesantes (Hunt). |

### Estructuras Internas
`HostReport { target, ip, ports: [PortDetail] }`
`PortDetail { port, state, service }`

### JSONL RustScan
Cada línea: `{ "ip": "1.2.3.4", "ports": [22,80,...] }`.

---
## 8. Reglas Dinámicas (`rules.yaml`)
Estructura básica:
```yaml
rules:
  - name: banner_grab
    ports: [22,80]
    cmds:
      - "nc -vz {ip} {port}"
  - name: servicio_http
    service_regex: "(?i)http"
    cmds:
      - "curl -m 5 -I http://{ip}:{port}"
```
Campos:
- `name`: identificador lógico.
- `ports`: lista de puertos concretos (match directo).
- `service_regex`: regex sobre el campo `service` parseado de Nmap.
- `cmds`: comandos a ejecutar; placeholders disponibles:
  - `{ip}`, `{target}`, `{port}`, `{service}`.

Si coincide por puerto o regex de servicio → se ejecutan todos los comandos listados. Salida guardada en log.

---
## 9. Reanudación y Confirmación `tcpwrapped`
- `--resume`: si existe `out/<ip>/nmap.xml`, se omite escaneo (útil para retomar ejecuciones largas).
- `--confirm-wrapped`: localiza puertos con servicio `tcpwrapped` y lanza re‑escaneo focal (-sT primero, fallback -sS) para intentar clarificar estado/servicio.

---
## 10. Filtros de Puertos
- `--hide-tcpwrapped`: excluye puertos cuyo servicio sea `tcpwrapped` en salidas resumidas/exports.
- `--only-open`: descarta puertos que no estén en estado `open` antes de exportar.

Los filtros se aplican tanto para conteos como para determinar si un host es "interesante".

---
## 11. Manejo de Dorks
`build_dork_from_keywords` transforma CSV de palabras clave en cláusulas AND:
- `chile` o `cl` → `country:CL`
- `.cl` (TLD simple) → búsqueda en `ssl`, `http.title`, `http.html`
- FQDN / dominio → hostname + certificados
- Palabras municipales (`muni`, `municipalidad`, etc.) → título/HTML/organización con "Municipalidad"
- Token de 2 letras (ISO probable) → `country:XX`
- Otros términos → OR de campos `http.title`, `http.html`, `org`, `product`.

Se deduplican cláusulas equivalentes.

Fallback a `country:CL` si `/count` devuelve error (timeout / 500).

---
## 12. Ejemplos de Uso
### Pipeline completo simple
```bash
shodan-pipeline full --keywords 'chile,.cl' --limit 200 --pages 20 \
  --hunt --hunt-needed 5 --hunt-min-open 3 --hunt-batch 5 \
  --nmap-concurrency 2 --rs-concurrency 16
```

### Adaptativo hasta 10 hosts con ≥2 puertos abiertos
```bash
shodan-pipeline full --keywords 'chile,.cl' --limit 400 --pages 30 \
  --interesting-target 10 --interesting-min-open 2
```

### Matriz de puertos fija
```bash
shodan-pipeline full --keywords 'chile' --fixed-ports '22,80,443,8000-8100' --limit 100
```

### Modo Intel (solo IPs)
```bash
shodan-pipeline intel --keywords 'chile,.cl' --limit 100 --pages 10
cat out/ips.txt
```

### Solo RustScan sobre archivo
```bash
shodan-pipeline rustscan --input-targets objetivos.txt --timeout-ms 2000 --batch 500 --concurrency 64
```

### Solo Nmap usando JSONL previo
```bash
shodan-pipeline nmap --input-jsonl resultados.rustscan.jsonl --nmap-extra '-sT -sV -Pn'
```

### Guardar API key
```bash
shodan-pipeline config --set $SHODAN_API_KEY
```

---
## 13. Errores Comunes y Consejos
| Situación | Explicación / Solución |
|-----------|------------------------|
| 429 en Shodan | Límite de rate; el código reintenta con backoff y salta página si persiste. Reducir `--pages` o `--limit`. |
| Nmap falla con `-sS` sin root | El normalizador reemplaza por `-sT`; se avisa en stderr. |
| Muy pocos puertos abiertos | Ajustar `--version-intensity`, quitar `--only-open`, o no ocultar `tcpwrapped`. |
| Dork inválido / 500 | Simplificar keywords; el pipeline cae a `country:CL`. |
| Ejecución lenta | Bajar concurrencia, limitar puertos con `--fixed-ports`, o usar Nmap-only env var en adaptativo/hunt. |
| Faltan IPs interesantes en adaptativo | Aumentar `--limit`, `--pages`, o reducir umbral `--interesting-min-open`. |

---
## 14. Roadmap / Ideas Futuras
- Integración opcional con bases de datos (SQLite) para histórico.
- Export HTML y/o Jupyter notebook automático.
- Modo incremental diario (diferencias vs run anterior).
- Soporte IPv6 (pendiente de validación Shodan + Nmap flags).
- Clasificación de servicios mediante fingerprint adicional.
- Soporte de listas de exclusión (`--exclude-ports`, `--exclude-hosts`).

---

---
## Créditos
Construido sobre:
- `reqwest`, `tokio`, `indicatif`, `quick-xml`, `serde`, `csv`, `clap`.
- Herramientas externas: **Shodan**, **RustScan**, **Nmap**.

---
¡Contribuciones y PRs son bienvenidos!
