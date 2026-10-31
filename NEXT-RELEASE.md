# Next Release — v0.4.1 (planned)

Two fixes are scheduled: terminal menu frame alignment and ASN scan preflight.

## Fix: terminal SCAN MENU frame alignment

**Status:** planned, not implemented.

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

**Status:** planned, not implemented.

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
are planned for Linux AMD64 v0.4.1. Release only after successful CI.
