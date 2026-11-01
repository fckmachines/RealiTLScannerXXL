# RealiTLScanner (Rust)

A fast TLS scanner that probes IPs, CIDRs, or domains for servers suitable as a Reality front: TLS 1.3, X25519 key exchange, HTTP/2 (`h2`) ALPN, and a non-empty certificate chain. Rust rewrite of [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner).

## Quick install — Linux AMD64

This fork provides prebuilt **Linux x86_64 (AMD64)** binaries in
[GitHub Releases](https://github.com/fckmachines/RealiTLScannerXXL/releases).
ARM64 builds are not published. Debian 13 and Ubuntu 24.04+ are the intended hosts.

Download the installer and run it (no Rust toolchain or compilation needed):

```bash
curl -fL https://raw.githubusercontent.com/fckmachines/RealiTLScannerXXL/main/install.sh -o install.sh
bash install.sh
```

The installer queries the latest GitHub Release, downloads `realitlscanner-linux-amd64`
and `SHA256SUMS`, verifies SHA-256 and the binary's version, and then atomically
installs it at `/usr/local/bin/realitlscanner` (using sudo when required).
If the installed version is current, it does nothing. It does not automatically downgrade
a newer local version.

```bash
bash install.sh --update      # Check and update, without compiling
bash install.sh --version     # Installed version
bash install.sh --uninstall   # Remove binary
bash install.sh --build       # Explicit source build (Debian/Ubuntu; Cargo cache retained)
realitlscanner --help
```

A release is published automatically **after tests and a successful AMD64 build** on
`main`, but only when the version in `Cargo.toml` does not already have a release.
Do not expect an installer downloaded from a feature branch to work until its first
release is visible in GitHub Releases.

## FAST SCAN — Masscan + Rust DEEP SCAN (v0.5.0)

**Masscan is the only FAST engine.** Existing Rust/Tokio TLS scanning remains
the DEEP engine. The menu defaults to FAST for ASN, CIDR and file-based IPv4
searches; a lone bare IP retains the legacy DEEP scan. CLI mode is backwards
compatible and requires an explicit `--fast` flag.

On Debian 13 (Trixie), install the optional operating-system dependency:

```bash
sudo apt-get update
sudo apt-get install -y masscan
```

Masscan performs raw SYN transmission and normally needs root or suitable
network capabilities. Run FAST scans only where you are authorized to do so.
**Do not automatically grant capabilities to the Rust binary.** Masscan may
be blocked by a VPS provider or network/firewall. The installer does **not**
modify nftables, source ports, routing, or firewall rules.

```bash
# Two-stage ASN sample: 4096 IPs, rate limited to 100 packets/s
sudo realitlscanner --asn AS14618 --max-ips 4096 \
  --fast --fast-rate 100 --fast-wait 5 \
  --thread 64 --timeout 5 --reality-sni --out results.csv

# Finite CIDR scan
sudo realitlscanner --addr 192.0.2.0/24 --fast --fast-rate 500

# Legacy DEEP-only scan, no Masscan
realitlscanner --asn AS14618 --max-ips 4096 --reality-sni
```

`192.0.2.0/24` is an RFC 5737 **documentation-only** CIDR. Replace it with
an authorized network.

FAST workflow:

1. Resolve ASN **once**, select partial/full unique IPv4 targets (from v0.4.1).
2. Write up to **5 million** finite target IPv4s to a private temporary file.
3. Execute Masscan with explicit target list, specified TCP port, packet-rate
   ceiling and bounded response wait.
4. Parse unique `open tcp PORT IP` results. Only those IPs reach Rust's
   original TLS 1.3 / HTTP/2 / certificate / DNS / IP-pinned HTTPS checks.
5. Keep normal CSV results for DEEP candidates, and remove temporary files.

FAST and DEEP counters are different: `[FAST]` reports targets and open TCP
ports, while the end summary counts only hosts reaching DEEP. A SYN-ACK is
not proof of a valid TLS service, and Masscan can miss ports when the VPS
provider drops probes or responses. In that case, use `--fast-wait`, lower
`--fast-rate` or switch to DEEP-only.

`--fast` accepts finite IPv4/CIDR targets, an ASN, or an IPv4-only input
file. It does not accept domains, IPv6, `--url`, or a lone bare `--addr IP`
(which activates the legacy infinite neighbor walk). Use `IP/32` for a
single finite address. FAST mode refuses over 5 million enumerated inputs
rather than exhausting disk space unexpectedly.

`--fast-rate` defaults to **100 packets/second**, configurable from 1 to
100000; higher rates are not automatically safer or more accurate. `--fast-wait`
defaults to **5 seconds** (range 1–60). Neither option alters DEEP timeouts
or its thread count.

## Ctrl+C recovery and partial-result processing (v0.5.4)

The first **Ctrl+C** in an interactive terminal **pauses** rather than
immediately ending the scan.

- **During FAST (Masscan):** already-reported `open tcp` IPv4 results are
  captured continuously via Masscan list output to stdout with
  `--output-flush`. Masscan stops; you can select **[1]** to run the usual
  Rust/Tokio DEEP validation on those *already found* IPs, **[2]** to save
  them to a recovery file, or **[0]** to exit with recovery saved. An
  interrupted FAST with no open IPs exits without inventing candidates.
- **During DEEP:** new probe starts stop. In-flight checks complete with
  their normal timeout, and the current CSV writer **flushes before**
  showing the menu. Option **[1]** resumes DEEP for the queued IPs without
  re-running Masscan, **[2]** saves remaining IPs and exits, **[0]**
  finishes safely and auto-saves any pending targets.
- **Noninteractive** (cron/pipes/--domains-only): no prompts; Ctrl+C
  checkpoints unprocessed targets if any, flushes verified CSV, reports
  the recovery file to stderr and exits with status **130**.
- A **second Ctrl+C** while already pausing forces prompt exit or
  cancels DEEP in-flight tasks; completed CSV records are flushed, the
  pending queue is saved, and the process exits with 130.
- Recovery files are uniquely named
  `realitlscanner-pending-<pid>-<stamp>-<n>.txt` in the output directory,
  created with mode **0600**, without overwriting any other files.
  Restore saved targets with `--in FILE` (DEEP-only without `--fast`).

The recovery file lists unprocessed targets / Masscan discoveries, **not**
hosts that passed TLS/DNS/HTTPS. Only accepted verified candidates appear
in `out.csv`. Repeated new scans without recovery still obey the
previous CSV overwrite semantics: use distinct `--out` paths to retain
earlier sessions. Prompts are never printed on stdout with `--domains-only`.

Note: this implements safe interruption rather than resumable Masscan
packet-level progress. It does **not** automatically resume checking the
original ASN after an interruption.

## v0.5.5 — FAST and DEEP progress indicators

When stderr is attached to a terminal, both scanning phases print progress
every two seconds. Example:

```text
[FAST] 2500/4096 (61.0%) | осталось 1596 | 98.5 IP/с | ETA 0m 17s [оценка SYN]
[DEEP] 68/213 (31.9%) | осталось 145 | 8.0 IP/с | ETA 0m 19s
```

- **FAST**: full target count comes from the prepared IP list. Masscan
  does not expose a reliable packet-sent counter through list output,
  so *processed* and ETA here are explicitly a **rate-based estimate**
  (`--fast-rate` times time elapsed), **not** evidence those SYN packets
  were actually transmitted or that hosts replied. At the end a separate
  line reports the unique IP addresses with confirmed open TCP ports.
- **DEEP**: completed count is actual completed TLS/DNS/HTTPS probes.
  When started from FAST, its exact total is the number of unique IPs
  with open TCP ports; when started from ASN or an inline finite CIDR/IP
  list, the exact total is known up front. If DEEP resumes after Ctrl+C,
  the total is recalculated from processed and queued targets.
- For streaming `--in` and `--url` sources and the legacy infinite-IP
  walk, the complete target count is not known in advance and progress
  shows `всего ?`, `осталось ?`, `ETA ?`. On completion, final
  processed count remains accurate; no fictitious percentage is printed.
- Progress goes exclusively to stderr; `--domains-only` leaves stdout
  reserved for found domain names. Non-TTY batch runs do not emit periodic
  progress chatter, but end-of-run statistics are unchanged.
- The existing Ctrl+C recovery introduced in v0.5.4 is retained.
  Progress pauses while interruption choices are displayed and resumes
  on the remaining collected targets without re-running Masscan.

No performance/traffic presets changed. Existing default is 100 SYN/s,
10 new DEEP probes/s, and 20-character certificate-domain limit.
Low rates do not guarantee the hosting provider accepts scanning.

## Nine scan speed presets (v0.5.3)

Interactive menu **[5] Скорость** now has nine ordered presets, a custom
option **[10]**, and **[0]** to return without changing the current speed.

| Key | Preset | FAST: Masscan SYN packets/s | DEEP: new probes/s |
| --- | --- | ---: | ---: |
| [1] | Минимальная | 5 | 1 |
| [2] | Очень тихая | 10 | 1 |
| [3] | Тихая | 25 | 2 |
| [4] | Осторожная | 50 | 5 |
| [5] | Стандартная (default) | 100 | 10 |
| [6] | Умеренно быстрая | 250 | 20 |
| [7] | Быстрая | 500 | 40 |
| [8] | Высокая | 1000 | 80 |
| [9] | Очень высокая | 2000 | 100 |

No scan engine, limits, or CLI flag changed. The existing defaults
remain **100 SYN/s and 10 DEEP/s**. Selected rates apply to both
interactive ASN scans and CIDR/file scans. Custom values use the existing
`--fast-rate` range 1..100000 and `--deep-rate` range 1..1000.

A preset controls starts, not *all* packets/second or bandwidth: TLS,
DNS, HTTPS, TCP retransmissions and other VPS traffic contribute.
High rates can trigger provider restrictions even on authorized
networks; use a low profile and follow the hosting provider's AUP.

## VPS-friendly rate limits and result locations (v0.5.2)

Defaults have been reduced to **20 Unicode characters** for input domains
and certificate Common Names (CNs), **100 SYN packets per second** for
Masscan FAST discovery and **10 new DEEP probes per second**. The global
DEEP start-rate gate is shared across all worker tasks; `--thread` still
limits how many slow or overlapping deep checks may be in flight. Neither
rate is a guaranteed cap on **all outgoing packets**, as TCP handshakes,
DNS and HTTPS generate additional traffic. Low rates do **not** guarantee
a VPS provider will allow scanning; comply with the provider's AUP and
scan only authorized ranges.

In the interactive menu choose **[5] Скорость** for nine profiles,
ranging from 5 SYN/s and 1 DEEP/s to 2000 SYN/s and 100 DEEP/s,
or **[10]** for custom values (see v0.5.3 table above). A low-rate
profile is preferable when the provider's policy or traffic budget is
uncertain; the operator must still obtain authorization.

```bash
# An authorized finite IPv4 range; gentle two-stage scan:
sudo realitlscanner --addr 192.0.2.0/24 --fast \
  --fast-rate 25 --deep-rate 2 --thread 8 --max-domain-length 20 \
  --reality-sni --out results.csv

# CLI defaults for FAST are 100 SYN/s and 10 DEEP probe starts/s:
sudo realitlscanner --addr 192.0.2.0/24 --fast --reality-sni
```

Use `--deep-rate N` to limit DEEP starts (1..1000/s), including
DEEP-only runs; `--fast-rate N` controls Masscan's SYN send rate
(1..100000/s). For intentionally slower operation lower either value.
Masscan has separate `--fast-wait` (seconds to collect replies), and
`--timeout` is a per-attempt TLS/HTTPS wait, not the scan pacing.

**Results:** `out.csv` (or `--out PATH`) contains only candidates
that have passed all enabled TLS/DNS/HTTPS checks, with IP, origin,
certificate CN, issuer and geographic country code. Relative paths are
resolved from the **working directory**, not `/usr/local/bin`. Rejections
only affect summary counters. FAST SYN responses are held in private
temporary files for DEEP handoff and deleted after the run; the program
does not persist a list of every tested IP.

## Domain-length filter and English confirmations (v0.5.1)

RealiTLScannerXXL rejects certificate Common Names (CNs) longer than **20
Unicode characters by default** (since v0.5.2). This runs immediately after the TLS
handshake and certificate inspection, **before** optional forward-DNS
verification and IP-pinned HTTPS requests, saving time on unsuitable long
hostnames. If the input itself is a domain (rather than an IP), overlong
hostnames are skipped before any DNS or TCP connection.

```bash
# Default cap: 20 characters
realitlscanner --addr 192.0.2.0/24 --reality-sni

# More restrictive: max 25 certificate CN characters
realitlscanner --addr 192.0.2.0/24 --max-domain-length 25 --reality-sni

# Disable domain length filtering
realitlscanner --addr 192.0.2.0/24 --max-domain-length 0 --reality-sni
```

In the interactive menu use **[4] Max domain length** to configure the
limit (default 20; 0 disables filtering) before choosing an ASN or target
source. The setting is applied to both FAST→DEEP and DEEP-only scans.

This checks the **certificate CN**, which is the hostname currently used by
the existing scanner for its SNI candidates. It does not inspect or limit
all alternative names (SANs) in the certificate. A limit of 20 can exclude
otherwise valid targets; raise the limit if you prefer completeness.

Confirmation prompts now use `Start scan? [y/N]` (default **No**) and
`Type YES to confirm full scan:` instead of Cyrillic confirmation input.
The rest of the interactive menu remains Russian.

## Interactive menu and VPS network identity

Run `realitlscanner` without arguments in a terminal to open the menu (FAST mode for finite IPv4 ranges requires the optional Masscan package and network privileges):

```text
IPv4 (исходящий): 203.0.113.10
ASN (RIPE RIS):   AS64500
Сеть:             EXAMPLE-NET
BGP-префикс:      203.0.113.0/24

[1] Сканировать IP / CIDR / несколько диапазонов
[2] Сканировать сети по ASN (RIPEstat)
[3] Сканировать IP/CIDR из файла
[4] Макс. длина домена: 20
[5] Скорость: 100 SYN/с · 10 DEEP/с
[0] Выход
```

The banner and network identity are only printed on interactive terminals and
are suppressed by `--domains-only`. `--no-network-info` disables external
network identity lookups when the scanner is run with CLI flags.

The IPv4 value is the **outbound public address** as seen by external services,
not necessarily the private IP on the VPS interface (e.g. behind NAT). The ASN
and announced BGP prefix are resolved using RIPEstat RIS routing information
and may be delayed; multiple origin ASNs are possible. Failure to query public
IP or RIPEstat does not prevent scanning.

### ASN scanning (IPv4) — v0.4.1

When you select **[2]** in the interactive menu, the program first
loads the ASN's observed IPv4 prefixes from RIPEstat and displays the
**complete number of unique IPv4 addresses** (CIDR overlaps are merged).
Before scanning or creating `out.csv` you can choose:

- **[1]** scan at most 4096 unique IPv4 addresses, evenly distributed
  over the ASN's observed address space
- **[2]** scan every observed IPv4 address, after entering `YES`
- **[3]** set your own maximum and confirm the selected count
- **[0]** cancel and return to the main menu without touching results

```bash
# Scan up to 4096 IPs (even when the ASN contains millions):
realitlscanner --asn AS14618 --reality-sni

# Scan at most 10,000 unique IPs distributed throughout the ASN:
realitlscanner --asn AS14618 --max-ips 10000 --reality-sni

# Scan the entire observed ASN (explicit, may be huge):
realitlscanner --asn AS14618 --all --reality-sni
```

The program prints "Будет проверено: N из TOTAL" **before** starting
scanning. Noninteractive partial scans print a warning on stderr, preserving
machine-readable stdout in `--domains-only` mode. The ASN preflight
never creates/truncates output when it fails.

The "TOTAL" number describes the unique IPv4 addresses covered by
[RIPEstat announced-prefixes](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes)
observations over a time window. It does not guarantee that those addresses
are currently announced or reachable. The default cap is **4096 probes**,
**not** a maximum permitted ASN size; the program no longer fails just
because an ASN contains more addresses than the cap.

Only scan IP ranges that you are authorized to probe.

## Scan more addresses

For a controlled scan of a CIDR, use `--addr` with `/24` (256 IPs),
`/20` (4,096 IPs), or another range you are authorized to probe.
Single bare IPs still use the original **infinite neighbour scan**; specify
`/32` to probe exactly one IP.

```bash
realitlscanner --addr 192.0.2.0/24 --thread 32 --reality-sni --out results.csv
realitlscanner --addr "192.0.2.0/24,198.51.100.0/24" --thread 32 --reality-sni
realitlscanner --in my-ranges.txt --thread 32 --reality-sni --out results.csv
```

The comma-separated `--addr` form always terminates after its finite list,
including if one entry is a bare IP. `--in` accepts one IP/CIDR/domain per line.
Use only ranges you have permission to probe. The scanner shows a candidate table,
progress every three seconds in an interactive terminal, and a final rejection
breakdown. `--domains-only` keeps stdout machine-readable and disables the UI.

In `--reality-sni` and `--check-http` mode, HTTPS is **pinned to the scanned
IP**, with the certificate CN as SNI and Host and normal certificate validation.
Redirects are **not followed** (301/302 are accepted statuses), so the check
cannot accidentally switch to a different IP. This improves precision; it does
not prove end-to-end Xray REALITY compatibility.

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

# Concurrent probe tasks (default: 32)
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
| `--asn <ASN>` | — | Scan RIPEstat-observed IPv4 prefixes for an ASN |
| `--max-ips <N>` | `4096` | Maximum IPv4 addresses sampled from the ASN |
| `--all` | off | Scan entire observed ASN (explicit opt-in) |
| `--no-network-info` | off | Suppress public IPv4/ASN lookup beneath banner |
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
| `--check-http` | off | Post-TLS IP-pinned HTTPS GET `/` check (auto-enabled by `--reality-sni`) |
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

After a feasible TLS handshake the scanner issues an IP-pinned `GET https://{cert_cn}/` via reqwest, using the certificate CN as SNI and Host, and requires:
- HTTP status 200, 301, or 302 (redirects are not followed)
- Body does not match a parked-page marker (`"domain is for sale"`, known parking providers like HugeDomains/Sedo/ParkingCrew/Bodis, etc.)

The probe connects directly to the IP under investigation, not the domain's public DNS result. The CN determines TLS SNI and HTTP Host. It checks the scanned endpoint rather than an unrelated host. `--reality-sni` automatically enables `--check-http`; the flags can also be used independently.

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
