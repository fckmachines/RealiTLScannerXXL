# RealiTLScanner (Rust)

A fast TLS scanner that probes IPs, CIDRs, or domains for servers suitable as a Reality front: TLS 1.3, X25519 key exchange, HTTP/2 (`h2`) ALPN, and a non-empty certificate chain. Rust rewrite of [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner).

## Building

Requirement: Rust 1.75+ (stable).

```bash
cargo build --release
# Binary: target/release/realitlscanner
```

## Usage

> It is recommended to run this tool locally. Running large scans from a VPS may cause the provider to flag the instance.

```bash
# Show help
./target/release/realitlscanner --help

# Scan a single IP, CIDR, or domain
./target/release/realitlscanner --addr 1.2.3.4
# Note: a single IP or domain implicitly enables infinite mode
#       (walks outward from the given address until ctrl-C)

# Scan a list of targets from a file (one per line)
./target/release/realitlscanner --in in.txt

# Crawl a URL for domains and scan them
./target/release/realitlscanner --url https://launchpad.net/ubuntu/+archivemirrors

# Custom port (default: 443)
./target/release/realitlscanner --addr 1.1.1.1 --port 443

# Verbose output (debug-level logs, including failed/infeasible targets)
./target/release/realitlscanner --addr 1.2.3.0/24 -v

# Output CSV path (default: out.csv; empty string disables file output)
./target/release/realitlscanner --addr www.microsoft.com --out file.csv

# Concurrent probe tasks (default: 2)
./target/release/realitlscanner --addr wiki.ubuntu.com --thread 100

# Per-target timeout in seconds (default: 10)
./target/release/realitlscanner --addr 107.172.1.1/16 --timeout 5

# Include IPv6 results in addition to IPv4
./target/release/realitlscanner --addr 2001:db8::/120 --46

# Stream only feasible cert domains to stdout, one per line
# (CSV still goes to --out; logs go to stderr so stdout stays pipe-safe)
./target/release/realitlscanner --addr 1.1.1.0/24 --domains-only --out "" 2>/dev/null | sort -u

# Reality-SNI mode: strict filter for usable Xray Reality `dest` targets.
# Rejects wildcard CNs, shared-CDN certs, hosts that fail DNS forward-verify,
# and (implicitly) runs an HTTP GET / check against a parked-page blocklist.
./target/release/realitlscanner --addr 104.16.0.0/16 --thread 50 --reality-sni --domains-only --out sni.csv 2>/dev/null

# Same thing but also exclude hosts geolocated in RU/CN/IR
./target/release/realitlscanner --addr 104.16.0.0/16 --thread 50 --reality-sni --exclude-geo RU,CN,IR --out sni.csv

# Use the HTTP check without the strict Reality filter (just "is it alive")
./target/release/realitlscanner --in targets.txt --check-http --out live.csv

# Custom MaxMind DB path (default: Country.mmdb next to the binary)
./target/release/realitlscanner --addr 1.1.1.1 --mmdb /path/to/Country.mmdb

./target/release/realitlscanner --addr 104.16.0.0/16 --thread 50 --reality-sni --exclude-geo RU,CN,IR --domains-only --out sni.csv
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--addr <TARGET>` | — | IP, CIDR, or domain to scan (mutually exclusive with `--in`/`--url`) |
| `--in <FILE>` | — | File with targets, one per line |
| `--url <URL>` | — | URL to crawl for domains |
| `--port <N>` | `443` | HTTPS port |
| `--thread <N>` | `2` | Concurrent probe tasks |
| `--out <PATH>` | `out.csv` | Output CSV path (empty disables file output) |
| `--timeout <SECS>` | `10` | Per-target timeout |
| `-v, --verbose` | off | Debug-level logging |
| `--46` | off | Enable IPv6 in addition to IPv4 |
| `--domains-only` | off | Also print cert domains to stdout (pipe-safe) |
| `--reality-sni` | off | Strict filter for Xray Reality `dest` (see below) |
| `--exclude-geo <LIST>` | none | Comma-separated ISO country codes to drop |
| `--check-http` | off | Post-TLS HTTP GET `/` check (auto-enabled by `--reality-sni`) |
| `--mmdb <PATH>` | `Country.mmdb` | Path to MaxMind GeoLite2/GeoIP2 Country database |

### `--reality-sni`

Turns on a strict post-probe filter that only emits hosts suitable as the `dest` (SNI) of an Xray Reality configuration. On top of the default feasibility check (TLS 1.3 + `h2` + X25519 + non-empty CN/issuer) the filter also requires:

1. **Concrete CN** — wildcard CNs (`*.example.com`) are rejected since Reality needs a literal hostname.
2. **No shared-CDN cert** — CNs ending in a known multi-tenant SSL suffix are rejected. Current blocklist covers Cloudflare shared SSL, Akamai, AWS CloudFront/S3, Azure Front Door / App Service, Fastly, Heroku, Vercel, Netlify, GitHub Pages and a handful of smaller CDNs.
3. **Forward-verify** — the cert CN must DNS-resolve to an IP set that includes the probed IP. This rejects accidental matches (unrelated cert served from a shared-hosting IP) at the cost of occasionally dropping CDN-fronted sites whose anycast returns different IPs per query.
4. **HTTP GET `/`** — `--reality-sni` implies `--check-http` (see below).

Geo filtering is not part of `--reality-sni` — pair it with `--exclude-geo RU,CN,IR` (or any other list) if you want to drop hosts from specific jurisdictions.

The filter is aggressive by design — expect a large drop in hit count versus a plain scan. What remains should be directly drop-in usable as a Reality `dest`.

### `--exclude-geo <LIST>`

Comma-separated list of ISO-2 country codes to drop from results. Case-insensitive. Works with or without `--reality-sni`. Requires a working `Country.mmdb` — without it every host reports `N/A` and nothing is excluded.

```bash
--exclude-geo RU,CN,IR       # drop Russia, China, Iran
--exclude-geo ru,cn          # same (case-insensitive)
```

### `--check-http`

After a feasible TLS handshake the scanner issues `GET https://{cert_cn}/` via reqwest and requires:
- HTTP status 200, 301, or 302 (redirects are followed up to 3 hops)
- Body does not match a parked-page marker (`"domain is for sale"`, known parking providers like HugeDomains/Sedo/ParkingCrew/Bodis, etc.)

The probe uses the cert CN as the hostname, so DNS resolves it independently of the IP the TLS handshake happened on. This verifies the domain is a live public site, not just an orphan cert. `--reality-sni` automatically turns `--check-http` on; the two can also be used independently.

The HTTP check is the most expensive filter (one full TLS + HTTP round-trip per feasible candidate). It runs last in the filter chain so only hosts that survived the cheaper string/DNS checks pay the cost.

## Docker

```bash
docker build -t realitlscanner .

# Show help
docker run --rm realitlscanner --help

# Scan
docker run --rm realitlscanner --addr 1.1.1.1
```

The image bundles `Country.mmdb` alongside the binary at `/app`, so GeoIP works out of the box.

## GeoIP

GeoIP is optional. If `Country.mmdb` is present next to the binary (or explicitly passed via `--mmdb`), feasible results include the ISO-2 country code. Otherwise the `GEO_CODE` column is `N/A`.

Download a database from <https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb>.

## Example output

stderr / stdout logs:

```
2026-04-15T10:52:10Z INFO realitlscanner: DNS resolver: system config
2026-04-15T10:52:10Z INFO realitlscanner: GeoIP enabled
2026-04-15T10:52:10Z INFO realitlscanner: Started all scanning threads
2026-04-15T10:52:10Z INFO realitlscanner: Connected (feasible) ip=107.172.103.9 origin=107.172.103.9 tls=1.3 alpn=h2 cert_domain=rocky-linux.tk cert_issuer="Let's Encrypt" geo=US
2026-04-15T10:52:10Z INFO realitlscanner: Connected (feasible) ip=107.172.103.11 origin=107.172.103.11 tls=1.3 alpn=h2 cert_domain=rn.allinai.dev cert_issuer="Let's Encrypt" geo=US
2026-04-15T10:52:38Z INFO realitlscanner: Scanning completed elapsed=28.97s
```

CSV output:

```csv
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
202.70.64.2,ntc.net.np,*.ntc.net.np,"GlobalSign nv-sa",NP
196.200.160.70,mirror.marwan.ma,mirror.marwan.ma,"Let's Encrypt",MA
103.194.167.213,mirror.i3d.net,*.i3d.net,"Sectigo Limited",JP
194.127.172.131,nl.mirrors.clouvider.net,nl.mirrors.clouvider.net,"Let's Encrypt",NL
75.2.60.5,cesium.di.uminho.pt,cesium.di.uminho.pt,"Let's Encrypt",US
195.14.50.21,mirror.corbina.net,ftp.corbina.net,"Let's Encrypt",RU
```

## Notes vs the Go original

- TLS stack: `rustls` + `ring` provider, TLS 1.3 only, X25519 key exchange only, ALPN `h2` / `http/1.1`, insecure cert verifier (the point is to probe unknown certs).
- DNS: [hickory-resolver](https://github.com/hickory-dns/hickory-dns) — truly async, uses the host's system DNS config, falls back to Google DNS in sandboxed environments.
- CIDR iteration is lazy: a `/8` does not materialize 16M host structs up front.
- GeoIP lookups are lock-free via `Arc<maxminddb::Reader>`.
- Graceful Ctrl-C shutdown drains workers cleanly in infinite mode.
- New `--domains-only` flag streams feasible domains to stdout for piping into other tools.
