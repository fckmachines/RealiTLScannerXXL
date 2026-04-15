use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::sync::Arc;

pub type DnsResolver = Resolver<TokioConnectionProvider>;

/// Build a tokio-backed hickory resolver wrapped in `Arc` for cheap sharing
/// across worker tasks. Prefers the host's system resolver config (reads
/// `/etc/resolv.conf` on Unix and the Windows adapter DNS settings); falls
/// back to Google Public DNS if the system config is unreadable (e.g. minimal
/// containers, sandboxes).
pub fn build() -> Arc<DnsResolver> {
    let resolver = match Resolver::builder_tokio() {
        Ok(b) => {
            tracing::info!("DNS resolver: system config");
            b.build()
        }
        Err(e) => {
            tracing::warn!(error = %e, "system DNS unavailable, using Google DNS");
            Resolver::builder_with_config(
                ResolverConfig::google(),
                TokioConnectionProvider::default(),
            )
            .build()
        }
    };
    Arc::new(resolver)
}

/// Resolve `host` to a single IP, matching Go's `LookupIP` first-match rule.
/// Filters out IPv6 results unless `ipv6` is set.
pub async fn lookup_first(resolver: &DnsResolver, host: &str, ipv6: bool) -> Option<IpAddr> {
    match resolver.lookup_ip(host).await {
        Ok(response) => response.iter().find(|ip| ipv6 || ip.is_ipv4()),
        Err(e) => {
            tracing::debug!(host = %host, error = %e, "DNS lookup failed");
            None
        }
    }
}
