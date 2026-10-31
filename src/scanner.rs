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
use std::time::Duration;
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
    pub exclude_geo: Arc<Vec<String>>,
}

struct ProbeOk {
    alpn: Vec<u8>,
    version: Option<ProtocolVersion>,
    cn: String,
    issuer: String,
}

pub async fn probe(
    mut host: Host,
    connector: TlsConnector,
    dns: Arc<DnsResolver>,
    geo: Arc<Geo>,
    out: async_channel::Sender<Record>,
    params: &ProbeParams,
) -> Outcome {
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
        Ok::<_, anyhow::Error>(ProbeOk {
            alpn,
            version,
            cn,
            issuer,
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
                && r.alpn == b"h2"
                && !r.cn.is_empty()
                && !r.issuer.is_empty();
            if !feasible {
                tracing::debug!(
                    %ip, origin = %host.origin,
                    alpn = %String::from_utf8_lossy(&r.alpn),
                    cn = %r.cn, issuer = %r.issuer,
                    "TLS/ALPN/certificate incompatible"
                );
                return Outcome::TlsIncompatible;
            }

            let geo_code = geo.country_code(ip);
            if params.reality_sni && filter::is_wildcard_cn(&r.cn) {
                tracing::debug!(%ip, cn = %r.cn, "reality-sni: wildcard CN");
                return Outcome::WildcardCert;
            }
            if params.reality_sni && filter::is_shared_cdn_cn(&r.cn) {
                tracing::debug!(%ip, cn = %r.cn, "reality-sni: shared CDN cert");
                return Outcome::SharedCdn;
            }
            if !params.exclude_geo.is_empty()
                && filter::is_excluded_geo(&geo_code, &params.exclude_geo)
            {
                tracing::debug!(%ip, geo = %geo_code, "excluded geo");
                return Outcome::ExcludedGeo;
            }
            if params.reality_sni && !filter::forward_verify(&dns, &r.cn, ip).await {
                tracing::debug!(%ip, cn = %r.cn, "reality-sni: forward-verify failed");
                return Outcome::ForwardDnsFailed;
            }
            // This request uses r.cn for SNI and Host but forces TCP to the
            // scanned ip:port. No redirects are followed to other hosts.
            if params.check_http
                && !filter::check_http(&r.cn, ip, params.port, params.timeout).await
            {
                tracing::debug!(%ip, cn = %r.cn, "IP-pinned HTTPS check failed");
                return Outcome::HttpFailed;
            }

            let rec = Record {
                ip,
                origin: host.origin,
                cert_domain: r.cn,
                cert_issuer: r.issuer,
                geo: geo_code,
            };
            if out.send(rec).await.is_err() {
                tracing::warn!("results channel closed");
            }
            Outcome::Accepted
        }
    }
}
