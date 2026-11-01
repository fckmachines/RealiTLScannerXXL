# Release v0.6.1 — shipped (2026-11-01)

## Compact scan metadata and transparent scoring in offline HTML

Implemented in PR #14 and published after successful AMD64 test/build/CI:
https://github.com/fckmachines/RealiTLScannerXXL/releases/tag/v0.6.1.
Scope is **HTML presentation only**. No additional mandatory eligibility
filters, packet-rate modifications, changes to FAST/DEEP, Ctrl+C handling,
result filenames, SAN processing, CLI flags or existing CSV schema.

### Above results: compact 1–2-line scan summary

Show scan source (ASN / CIDR(s) / input file / URL), scan date/time,
requested target count versus actual probed count, matched candidates,
FAST and DEEP rates, and relevant ASN operator. For ASN scans, reuse the
existing RIPEstat operator name, ASN number, total covered IPv4 and
unique advertised prefixes from the **preflight result**. Do not confuse
an ASN operator with the RDAP registered IP-block holder. Display
a block holder only when actually verified through an authoritative
RDAP result; otherwise show 'не проверено'. For non-ASN input,
do not invent an ASN or full-scan percentage. Clearly mark sampled,
full, interrupted and unknown-size inputs. Avoid lengthy tables.

### In result rows: open website and copy bare SNI hostname

Requested 2026-11-01. Keep original sortable/searchable table and add
two distinct intuitive actions next to each selected certificate domain:

* Visible domain label itself is a hyperlink targeting
  `https://<validated candidate hostname>/` in a new tab, with
  `target="_blank" rel="noopener noreferrer"`. The literal page link
  contains the HTTPS scheme, but the visible label remains the bare domain.
* A nearby small copy button (accessible name "Скопировать домен")
  copies **only the exact selected SNI hostname** (e.g. `example.com`,
  optionally `www.example.com`), with **no** scheme, trailing slash,
  URL path, port or whitespace. Copy neither the scanned IP nor the
  certificate issuer. Display unobtrusive "Скопировано" only on success;
  provide selectable text and a short error on denied clipboard access.
* Make this work in an **offline `file://` HTML report** opened in
  Firefox and Waterfox: try the async Clipboard API in a browser-supported
  user gesture; fall back to a temporary selected textarea and
  `document.execCommand('copy')` if needed. Never claim copy succeeded if
  both mechanisms fail. Test in an actual local-file browser environment
  where possible; headless DOM checks alone are insufficient evidence.
* Treat certificate-derived names as **untrusted content**: escape text
  and HTML attributes; validate the hostname before producing an external
  `https:` link; reject URL schemes, controls and markup. Render as
  non-clickable/selectable text if invalid, without silently throwing
  away an otherwise accepted CSV row.
* Preserve original search, sorting, scoring, HTML-only offline
  operation, existing CSV schema, and unique per-run filenames.
  Do not create additional HTTP requests or perform any extra scan.
  No changes to acceptance filters, candidate counts or ratings.

Add regression checks for plain hostname copy value, HTML injection/
unsafe-link rejection, two distinct click targets, search/sort behavior
and offline clipboard fallback. This is a UI-only addition; no scanner
logic changes.

### Below results: one collapsed <details> section

Label: 'Рейтинг: методика и базовые 60 баллов'. Explain succinctly:

* Base +60 is assigned to **every result that passed the checks enabled
  for this particular scan**, not 60 separate measurements. Core checks:
  completed TLS 1.3 handshake with client X25519-only key exchange,
  negotiated HTTP/2 'h2', at least one certificate with nonempty issuer,
  a candidate CN/SAN hostname within the configured length cap.
* For --reality-sni add concrete non-wildcard candidate, named CDN
  suffix exclusion, DNS forward resolution including the scanned IP,
  and IP-pinned HTTPS request (SNI/Host, certificate hostname checked,
  allowed response 200/301/302, no known parked-page marker).
  Geo exclusion applies only if requested.
* Without --reality-sni some checks are **not** mandatory: do not claim
  they passed. --check-http is optional unless implied by --reality-sni.
  Never imply the initial TLS connection validated the certificate chain:
  its custom verifier deliberately skips that; the later HTTPS request
  does normal trust/hostname verification when enabled.
* Existing formula in src/output.rs is exactly:
  60 base + 10 iff selected candidate was a SAN alternative +
  10 iff HTTPS verification was enabled and passed + one of
  {15 if TLS <200ms, 8 if <500ms, 3 if <1000ms, 0 otherwise}.
  Max currently **95**, not 100; SAN's extra 10 are a heuristic and
  not evidence of greater reliability than CN.
* Neither the score nor its new explanation excludes additional domains.
  It does not prove long-term stability, geographic reachability,
  non-VPN/non-proxy content, trustworthiness, or actual Xray compatibility.
* Keep explanatory copy short, with a narrow compact table/summary;
  HTML must remain usable offline and safe to render with untrusted
  domain/issuer/organization strings properly escaped.

### Acceptance tests

1. Report from an ASN scan includes grounded operator/ASN and accurate
   sample/full counts; CIDR/file/URL reports do not fabricate ASN data.
2. Empty and interrupted scans do not display false completion stats.
3. Existing result table/search/sort still work; HTML has concise header
   and collapsed score details; CSS/markup remains offline.
4. Unit tests cover absent metadata, escaping, and score boundary bands.
5. Existing five-column CSV, no-overwrite filenames, SAN acceptance,
   v0.5.4 Ctrl+C and Masscan integration tests all remain passing.
6. Run test/build/smoke/real-Masscan-parser CI before any release.

---

# Release v0.5.5 — shipped (2026-11-01)

**Scope:** display exact completed/remaining/percentage and estimated
completion time for DEEP where a finite target count is known, and
explicitly labelled rate-based FAST estimates. Preserve the already
released v0.5.4 Ctrl+C handling. Keep CLI stdout clean for
`--domains-only`; do not claim exact totals for streaming sources.
Status: released after passing Rust tests, AMD64 build and smoke test. See https://github.com/fckmachines/RealiTLScannerXXL/releases/tag/v0.5.5 and PR #11.

---

# Release v0.5.4 — shipped (2026-11-01)

## Feature: graceful Ctrl+C with processing of partial scan results

**User request (2026-11-01):** Ctrl+C during scanning should **not immediately
exit**. Pause discovery or processing and offer to handle everything already
collected. This must work whether the signal arrives in Masscan FAST discovery
or the Rust/Tokio DEEP stage.

### Interaction: FAST scan interrupted

- First Ctrl+C means **stop sending new SYN probes** and finish collecting
  already-arrived results within a short bounded shutdown period.
- Safely stop and reap the Masscan child; do not lose the open TCP/443 IPs it
  has already reported. Replace the current all-or-nothing flow (Masscan runs
  to completion before its file is parsed) with incremental, durable parsing
  or a flushed on-disk journal. A partially written final line must be ignored,
  not counted as an IP. Never assume Masscan finishes normally after SIGINT.
- Deduplicate captured IPv4 addresses and show their exact count.
- In an interactive terminal, print a summary and offer:

```text
FAST SCAN paused (Ctrl+C).
Checked/attempted: <count, if reliably available>
TCP/443 open captured: <N> unique IPv4

[1] DEEP SCAN — verify the <N> IPs already found
[2] Save these IPs to a separate .txt file and exit
[0] Exit, preserving all completed results
Choice [1]:
```

Option [1] hands **only the collected IPs** to the existing TLS/DNS/HTTPS
workers; it must never restart FAST or continue probing unvisited targets.
Option [2] creates an explicit, reusable IP-only file, safely named without
overwriting an existing result. Option [0] exits cleanly and retains already
completed output; do not silently discard captured open-IP results—save the
recoverable list automatically if nonempty and tell the user its path.
If there are no captured open IPs, show that clearly and offer safe exit.

### Interaction: DEEP scan interrupted

- First Ctrl+C stops scheduling **new** TLS/HTTPS probes. Do not abort
  already-running probes; let them finish under their configured timeouts
  and **flush** the output writer to disk before presenting the menu.
- Clearly distinguish *already verified* accepted domains, *rejected*
  targets, and *unprocessed IPs found by FAST*.
- Present choices:

```text
DEEP SCAN paused (Ctrl+C).
Finished DEEP: <N>
Accepted candidates: <N>
Remaining collected IPs: <N>

[1] Continue DEEP on the remaining collected IPs (no new FAST)
[2] Save remaining IPs to .txt and finish
[0] Finish now, keeping verified CSV and saving unprocessed IPs
Choice [0]:
```

Ensure that in-flight results and final counts stay correct; any outstanding
IP targets must be recoverable and never falsely labelled "verified".
Do not truncate existing `out.csv` on interruption. When continuing,
preserve the same deduplication, domain-length cap, speed profile, and filter
settings from the original run.

### CLI/batch behavior and signals

- Ask only when stdin and stderr/stdout are attached to an **interactive TTY**.
  For pipes, cron and `--domains-only` batch workflows, **never block**:
  stop new work, finish bounded in-flight work, flush existing CSV/stdout,
  checkpoint unprocessed IPs when possible, report status on stderr,
  and return interrupt exit status 130.
- Keep `--domains-only` stdout exclusively for domain names, including
  interrupted runs; prompts and progress go to stderr/TTY.
- A *second* Ctrl+C during shutdown or the prompt should trigger a fast but
  still safe exit with a bounded flush/checkpoint, never an infinite wait.
  Errors from Masscan stop/reap, disk writes, or stdin EOF must be surfaced,
  not reported as a successful complete scan.
- Use a single well-defined cancellation coordinator for FAST, producer,
  DEEP worker queues, file writers and subprocesses; avoid orphaned Masscan
  processes and data races. Respect the existing 5M FAST target cap.
- Only save recovered IPs and verified results, **not** arbitrary scanned
  destinations or private workspaces to a world-readable file; preserve
  restrictive file permissions and warn about files containing target IPs.

### Acceptance and release gate

1. Ctrl+C during a partially completed FAST scan offers DEEP processing of
   captured open IPs, without continuing FAST; pending list is recoverable.
2. Ctrl+C during DEEP does not lose already accepted CSV rows or mistake
   queued IPs for checked results; user may continue, save, or exit.
3. First interruption does not immediately terminate an interactive scan.
   Zero-candidate, back-to-back signal, EOF and non-TTY runs behave safely.
4. Original `out.csv` content is not unexpectedly overwritten; completed
   result files are always flushed on clean interrupt.
5. Add deterministic integration tests using a simulated streaming Masscan
   process and synthetic TLS/DEEP results (no Internet probing in CI).
6. No regression in normal completion, FAST→DEEP performance/rate limits,
   ASN preflight, `--max-domain-length`, `--domains-only`, or installer.
7. Document operator-facing prompts, batch exit codes and recovery file paths.
8. Publish Linux AMD64 v0.5.4 **only after** Rust tests, release build, and
   interruption smoke tests pass in GitHub Actions.

**Current status:** implemented and released in v0.5.4. Tests included synthetic interrupted Masscan streaming, noninteractive interrupted DEEP over loopback, CSV append-on-resume, and private recovery file persistence. See [PR #9](https://github.com/fckmachines/RealiTLScannerXXL/pull/9) and [v0.5.4](https://github.com/fckmachines/RealiTLScannerXXL/releases/tag/v0.5.4). **Operational limitation:** this release salvages Masscan reports already flushed to stdout; an immediate second interruption may abandon an in-flight TLS probe, and no reliable exact number of SYN attempts is provided. Test interactively on the actual VPS to validate terminal signal UX.

---

## Earlier released plan (historical record)

# Release v0.4.1 — shipped (2026-10-31)

Both fixes were implemented and published in v0.4.1. This file retains the acceptance plan as a release record. See [v0.4.1](https://github.com/fckmachines/RealiTLScannerXXL/releases/tag/v0.4.1) and [PR #4](https://github.com/fckmachines/RealiTLScannerXXL/pull/4).

## Fix: terminal SCAN MENU frame alignment

**Status:** implemented, tested and released in v0.4.1.

Observed in v0.4.0 screenshot (2026-10-31): the right border of the SCAN MENU is misaligned and one of the rows extends beyond the frame. The first (longest) menu entry is a likely culprit. Current `src/menu.rs` renders each border/row using manually padded static strings.

### Required changes

- Centralize menu rendering: a single visible width for top/bottom borders, separator, and all rows.
- Compute padding from **display-cell width**, not UTF-8 byte count; Cyrillic and box-drawing glyphs must be handled correctly.
- No extra/missing `│` on the right, including the longest `[1] Сканировать IP / CIDR / несколько диапазонов` label.
- Handle narrow terminal widths gracefully (fit, wrap, or truncate) rather than rendering outside the border.
- Exclude ANSI colors/escapes from visible width; preserve existing hotkeys [1], [2], [3], [0] and navigation.
- Add tests for all menu rows and constrained widths.
- Confirm layout visually on Linux terminals.

### Acceptance criteria

1. Each frame row has equal display width; the right border is in the same column.
2. All labels fit in a regular 80-column terminal with no clipping.
3. `cargo test --locked` and release build pass in CI.
4. Publish Linux AMD64 v0.4.1 and upgrade with the existing `bash install.sh --update`; no compilation on the VPS.

## Fix: ASN scan should validate scope *before* starting

**Status:** implemented, tested and released in v0.4.1.

Observed on 2026-10-31 with menu option [2] and the detected ASN `AS14618`: the program printed
`SCAN | threads: 32` and `Результаты сохраняются в: out.csv`, then exited with
`AS содержит не менее 7168 IPv4-адресов (лимит 4096)`.

The 4096-IP safeguard is intentional and must remain, but discovering an oversized ASN
**after** starting workers/output is incorrect UX. In particular, the writer creates/truncates
`out.csv` before the producer validates the prefix set.

### Confirmed behavior for v0.4.1

The v0.4.0 message `не менее 7168 IPv4` is only a **lower bound**: its
prefix reader stops early when the cumulative count passes 4096. It does **not**
scan the first 4096 targets, and `7168` is not the full ASN size.

After preflight, display a concrete, complete count of **unique IPv4 addresses
covered by the returned RIPEstat prefixes**, with overlapping CIDRs merged.
The count describes that RIPEstat observation snapshot, not a guarantee of
currently reachable addresses or every prefix actually owned by the ASN.

Interactive choice after preview:

```text
ASN:          AS14618 — AMAZON-AES (example)
IPv4 networks: <calculated count>
IPv4 total:    <calculated unique count>
Scan limit:    4096

[1] Scan up to 4096 IPv4 from this ASN (distributed across prefixes)
[2] Scan entire observed ASN (<calculated total>) — confirm explicitly
[3] Change scan limit (N)
[0] Back to menu
```

For [1], scan **at most** N **unique** IPv4 addresses, spread across the ASN's
returned networks rather than silently taking only the first CIDRs. The UI
must label this a **partial sample**, not an exhaustive ASN scan. If the
observed ASN is smaller than N, scan all its addresses. [2] requires a separate
confirmation of the exact total and scope. [3] allows an explicit N and
displays `Будет проверено: min(N, total) из total` before starting.
No option starts a scan before a conscious menu selection.

Noninteractive behavior: `--asn AS14618` uses default `--max-ips 4096`
as a **maximum scan count**, not an error threshold, and prints the exact
total and `Частичная выборка: 4096 из <total> IPv4` to stderr when truncated.
`--max-ips N` scans at most N. Provide a separate opt-in `--all` flag for
the complete snapshot, with an explicit warning of the exact size.
`--domains-only` keeps stdout reserved exclusively for domains.

### Required changes

- Fetch RIPEstat observed IPv4 prefixes, normalize them, **merge overlaps**
  and calculate total unique IPv4 addresses before starting anything.
- Present detected network holder, ASN, observed prefix count, unique IPv4
  total and exact selected scan count in interactive mode.
- Generate deterministic, nonduplicated IP selection across the observed
  prefixes, with bounded memory for very large ASNs.
- Reuse the same fetched scan plan for execution (no second API lookup).
- Do not create/truncate `out.csv` during preflight, cancellation, or API
  errors. Handle invalid ASN or service failures within the menu.
- Preserve automatic ceiling of 4096 for default ASN scans, but never confuse
  the ceiling with a minimum-size requirement or total ASN capacity.
- Add tests for overlap deduplication, precise totals, bounded sampling,
  interactive partial/full confirmation, cancellation, and CLI flags.

### Acceptance criteria

1. The complete observed unique IPv4 count is shown **before** any `SCAN` line.
2. [1] checks at most N unique IPs selected across prefixes; it does not fail
   merely because the ASN contains more than N.
3. [2] can check all observed IPs **only after explicit confirmation**.
4. [3] adjusts N; both the selected count and total are clearly displayed.
5. Noninteractive default and `--max-ips N` complete partial scans with
   an unambiguous partial-coverage notice on stderr, never a false full-scan claim.
6. Rejected/cancelled preflight does not start workers or overwrite results.
7. No regression to `--addr`, `--in`, `--url`, `--domains-only`.
8. Rust tests, AMD64 release build and smoke checks pass in GitHub Actions.

**Scope:** terminal UI and ASN preflight. No changes to TLS/HTTP probe logic. Both fixes
are planned for Linux AMD64 v0.4.1. Released after passing CI (Rust unit tests, AMD64 release build and CSV-preservation smoke test).
