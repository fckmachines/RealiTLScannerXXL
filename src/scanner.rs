use crate::filter;
use crate::geo::Geo;
use crate::host::{Host, HostType};
use crate::output::Record;
use crate::resolver::{self, DnsResolver};
use crate::stats::Outcome;
use anyhow::anyhow;
use rustls::pki_types::ServerName;
use rustls::ProtocolVersion;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashSet;
use x509_parser::extensions::GeneralName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Per-probe configuration. Bundled into one struct so `probe()` keeps a
/// sane argument count after the `--reality-sni`, `--exclude-geo`, and
/// `--check-http` additions. Cheap to clone: `exclude_geo` is an `Arc`.
#[derive(Clone)]
pub struct ProbeParams {
    pub port: u16,
    pub timeout: Duration,
    pub ipv6: bool,
    pub reality_sni: bool,
    pub check_http: bool,
    pub max_domain_length: usize,
    pub exclude_geo: Arc<Vec<String>>,
}

struct ProbeOk {
    alpn: Vec<u8>,
    version: Option<ProtocolVersion>,
    cn: String,
    issuer: String,
    san_dns: Vec<String>,
}


fn candidate_names(cn: &str, sans: &[String], max_chars: usize, legacy_cn: bool) -> Vec<(String, bool)> {
    let mut names=Vec::new();
    let mut seen=HashSet::new();
    for (value, via_san) in std::iter::once((cn,false))
        .chain(sans.iter().map(|s|(s.as_str(),true))) {
        let name=value.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() || filter::is_domain_too_long(&name,max_chars) {continue;}
        // Preserve old DEEP-only semantics for non-REALITY scans: their
        // CN previously needed only to be nonempty. New SAN alternatives
        // always require a concrete DNS hostname.
        if (via_san || !legacy_cn) &&
            (name.starts_with("*.") || name.parse::<std::net::IpAddr>().is_ok()
             || !name.contains('.') || !crate::host::validate_domain(&name)) {
            continue;
        }
        if !seen.insert(name.clone()) {continue;}
        names.push((name, via_san));
        if names.len()==8 {break;}
    }
    names
}

#[cfg(test)]
mod candidate_tests {
    use super::*;
    #[test]
    fn cn_is_kept_and_san_expands_without_new_rejections() {
        let sans=vec!["www.example.org".into(),"legacy.test".into(),
            "*.example.org".into(),"toolong-subdomain.example.org".into(),
            "new.example.net".into()];
        let names=candidate_names("Legacy.Test",&sans,20,false);
        assert_eq!(names,vec![
            ("legacy.test".into(),false),
            ("www.example.org".into(),true),
            ("new.example.net".into(),true)
        ]);
        assert_eq!(candidate_names("", &["other.test".into()],20,false),
            vec![("other.test".into(),true)]);
        assert!(candidate_names("",&[],20,false).is_empty());
        assert_eq!(candidate_names("*.legacy.test",&[],20,true),
            vec![("*.legacy.test".into(),false)]);
        assert!(candidate_names("*.legacy.test",&[],20,false).is_empty());
    }
    #[test]
    fn huge_san_cert_capped_at_eight() {
        let many=(0..100).map(|i|format!("d{i}.example.org")).collect::<Vec<_>>();
        assert_eq!(candidate_names("example.org",&many,20,false).len(),8);
        assert!(candidate_names("long-domain.example.org",&[],20,false).is_empty());
    }
}

pub async fn probe(
    mut host: Host,
    connector: TlsConnector,
    dns: Arc<DnsResolver>,
    geo: Arc<Geo>,
    out: async_channel::Sender<Record>,
    params: &ProbeParams,
) -> Outcome {
    // Input domains can be discarded even before DNS and TCP/TLS work.
    if host.kind == HostType::Domain
        && filter::is_domain_too_long(&host.origin, params.max_domain_length)
    {
        tracing::debug!(origin = %host.origin, max = params.max_domain_length, "input domain too long");
        return Outcome::DomainTooLong;
    }

    // DNS if needed (matches Go's lazy LookupIP in ScanTLS). Uses hickory-
    // resolver so lookups are truly async and share a single query cache
    // across workers instead of hopping through the blocking-fs pool once
    // per probe like `tokio::net::lookup_host` does.
    if host.ip.is_none() {
        match resolver::lookup_first(&dns, &host.origin, params.ipv6).await {
            Some(ip) => host.ip = Some(ip),
            None => {
                tracing::debug!(origin = %host.origin, "no IP");
                return Outcome::DnsFailed;
            }
        }
    }

    let ip = host.ip.expect("ip resolved above");
    let addr = SocketAddr::new(ip, params.port);

    let tls_start = Instant::now();
    let probe_fut = async {
        let tcp = TcpStream::connect(addr).await?;

        let server_name: ServerName<'static> = match host.kind {
            HostType::Domain => ServerName::try_from(host.origin.clone())
                .map_err(|e| anyhow!("invalid server name: {e}"))?,
            _ => ServerName::IpAddress(ip.into()),
        };

        let tls = connector.connect(server_name, tcp).await?;
        let (_, conn) = tls.get_ref();
        let alpn = conn.alpn_protocol().map(|b| b.to_vec()).unwrap_or_default();
        let version = conn.protocol_version();
        let certs = conn
            .peer_certificates()
            .ok_or_else(|| anyhow!("no certs"))?;
        if certs.is_empty() {
            return Err(anyhow!("empty certs"));
        }
        let (_, parsed) = x509_parser::parse_x509_certificate(certs[0].as_ref())?;
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .unwrap_or("")
            .to_owned();
        let orgs: Vec<String> = parsed
            .issuer()
            .iter_organization()
            .filter_map(|a| a.as_str().ok().map(|s| s.to_owned()))
            .collect();
        let issuer = orgs.join(" | ");
        let san_dns=parsed.subject_alternative_name().ok().flatten()
            .map(|san| san.value.general_names.iter().filter_map(|name| {
                if let GeneralName::DNSName(value)=name {
                    Some(value.to_string())
                } else {None}
            }).collect::<Vec<_>>()).unwrap_or_default();
        Ok::<_, anyhow::Error>(ProbeOk {
            alpn,
            version,
            cn,
            issuer,
            san_dns,
        })
    };

    match tokio::time::timeout(params.timeout, probe_fut).await {
        Err(_) => {
            tracing::debug!(%ip, origin = %host.origin, "timeout");
            Outcome::ConnectionFailed
        }
        Ok(Err(e)) => {
            tracing::debug!(%ip, origin = %host.origin, error = %e, "probe failed");
            Outcome::ConnectionFailed
        }
        Ok(Ok(r)) => {
            let feasible = matches!(r.version, Some(ProtocolVersion::TLSv1_3))
                && r.alpn == b"h2" && !r.issuer.is_empty();
            if !feasible {
                tracing::debug!(%ip, "TLS/ALPN/issuer incompatible");
                return Outcome::TlsIncompatible;
            }
            let tls_ms=tls_start.elapsed().as_millis().min(u32::MAX as u128) as u32;
            let names=candidate_names(&r.cn,&r.san_dns,params.max_domain_length,!params.reality_sni);
            if names.is_empty() {
                if r.cn.is_empty() && r.san_dns.is_empty() {
                    return Outcome::TlsIncompatible;
                }
                return Outcome::DomainTooLong;
            }
            let geo_code=geo.country_code(ip);
            if !params.exclude_geo.is_empty()
                && filter::is_excluded_geo(&geo_code,&params.exclude_geo) {
                return Outcome::ExcludedGeo;
            }

            let mut had_forward_match=false;
            let mut had_filtered_name=false;
            for (name, via_san) in names {
                if params.reality_sni && filter::is_shared_cdn_cn(&name) {
                    had_filtered_name=true;
                    continue;
                }
                if params.reality_sni && !filter::forward_verify(&dns,&name,ip).await {
                    continue;
                }
                had_forward_match=true;
                if params.check_http
                    && !filter::check_http(&name,ip,params.port,params.timeout).await {
                    continue;
                }
                let rec=Record {
                    ip,
                    origin:host.origin.clone(),
                    cert_domain:name,
                    cert_issuer:r.issuer.clone(),
                    geo:geo_code,
                    tls_ms,
                    san_count:r.san_dns.len().min(u16::MAX as usize) as u16,
                    via_san,
                    verified_http:params.check_http,
                };
                if out.send(rec).await.is_err() {
                    tracing::warn!("results channel closed");
                }
                return Outcome::Accepted;
            }
            if params.check_http && had_forward_match {return Outcome::HttpFailed;}
            if params.reality_sni && had_filtered_name && !had_forward_match {
                return Outcome::SharedCdn;
            }
            if params.reality_sni {return Outcome::ForwardDnsFailed;}
            Outcome::TlsIncompatible
        }
    }
}
