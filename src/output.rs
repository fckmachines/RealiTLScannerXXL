use std::net::IpAddr;
use tokio::io::{AsyncWriteExt, BufWriter};

#[derive(Debug, Clone)]
pub struct Record {
    pub ip: IpAddr,
    pub origin: String,
    pub cert_domain: String,
    pub cert_issuer: String,
    pub geo: String,
}

/// Pure formatter for a single CSV row. Extracted so it can be unit-tested
/// without spinning up the async writer task and its file handle. The issuer
/// is quoted (matching Go) because it commonly contains commas, e.g.
/// `Let's Encrypt, Inc.`.
pub fn format_record(r: &Record) -> String {
    format!(
        "{},{},{},\"{}\",{}\n",
        r.ip, r.origin, r.cert_domain, r.cert_issuer, r.geo
    )
}

/// Writer task: consumes `Record`s from `rx`, optionally appending a CSV row to
/// `out_path` (empty string disables file output, matching Go's `io.Discard`),
/// and optionally echoing `cert_domain` to stdout when `--domains-only` is set.
pub async fn writer(
    rx: async_channel::Receiver<Record>,
    out_path: String,
    domains_only: bool,
) -> anyhow::Result<()> {
    // Wrap the output file in a BufWriter: every raw `write_all` on a
    // `tokio::fs::File` is dispatched to the blocking-fs pool, so at high
    // feasible rates we were paying one syscall hop per record. BufWriter
    // coalesces small CSV rows into page-sized flushes.
    let mut file = if out_path.is_empty() {
        None
    } else {
        let f = tokio::fs::File::create(&out_path).await?;
        let mut f = BufWriter::new(f);
        f.write_all(b"IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE\n")
            .await?;
        Some(f)
    };

    // Hoist the stdout handle out of the loop: constructing a fresh
    // `tokio::io::stdout()` each iteration re-entered the lock/init path.
    // Kept unbuffered with a per-record flush so downstream `grep` etc. do
    // not deadlock when `--domains-only` is piped.
    let mut stdout = if domains_only {
        Some(tokio::io::stdout())
    } else {
        None
    };

    let mut printed_header = false;
    while let Ok(rec) = rx.recv().await {
        if !domains_only {
            if !printed_header {
                println!("\n{:<40} {:<42} {:<6} {}", "IP", "CERTIFICATE DOMAIN", "GEO", "ISSUER");
                println!("{}", "-".repeat(105));
                printed_header = true;
            }
            println!(
                "{:<40} {:<42} {:<6} {}",
                rec.ip, rec.cert_domain, rec.geo, rec.cert_issuer
            );
        }
        if let Some(f) = file.as_mut() {
            let line = format_record(&rec);
            f.write_all(line.as_bytes()).await?;
        }
        if let Some(stdout) = stdout.as_mut() {
            stdout.write_all(rec.cert_domain.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    if let Some(mut f) = file {
        f.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_record_basic_row() {
        let rec = Record {
            ip: "1.2.3.4".parse().unwrap(),
            origin: "example.com".to_string(),
            cert_domain: "example.com".to_string(),
            cert_issuer: "Let's Encrypt".to_string(),
            geo: "US".to_string(),
        };
        assert_eq!(
            format_record(&rec),
            "1.2.3.4,example.com,example.com,\"Let's Encrypt\",US\n"
        );
    }

    #[test]
    fn format_record_quotes_issuer_with_commas() {
        // Issuers with commas (`Let's Encrypt, Inc.`) rely on the surrounding
        // quotes to keep the CSV well-formed. This is why the inner format
        // hard-codes quotes around the issuer only.
        let rec = Record {
            ip: "10.0.0.1".parse().unwrap(),
            origin: "10.0.0.1".to_string(),
            cert_domain: "foo.example".to_string(),
            cert_issuer: "Let's Encrypt, Inc.".to_string(),
            geo: "N/A".to_string(),
        };
        assert_eq!(
            format_record(&rec),
            "10.0.0.1,10.0.0.1,foo.example,\"Let's Encrypt, Inc.\",N/A\n"
        );
    }

    #[test]
    fn format_record_ipv6_row() {
        let rec = Record {
            ip: "::1".parse().unwrap(),
            origin: "::1".to_string(),
            cert_domain: "localhost".to_string(),
            cert_issuer: "Self".to_string(),
            geo: "N/A".to_string(),
        };
        assert_eq!(
            format_record(&rec),
            "::1,::1,localhost,\"Self\",N/A\n"
        );
    }

    #[test]
    fn format_record_ends_with_newline() {
        let rec = Record {
            ip: "8.8.8.8".parse().unwrap(),
            origin: "dns.google".to_string(),
            cert_domain: "dns.google".to_string(),
            cert_issuer: "Google".to_string(),
            geo: "US".to_string(),
        };
        let s = format_record(&rec);
        assert!(s.ends_with('\n'));
    }
}
