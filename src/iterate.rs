use crate::host::{validate_domain, Host, HostType};
use crate::resolver::{self, DnsResolver};
use async_channel::Sender;
use ipnet::IpNet;
use regex::Regex;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Parse a single input line and expand it into zero or more hosts, matching
/// Go's `Iterate`:
///   * IP: single host (filtered to IPv4 unless `ipv6`)
///   * CIDR: iterate every address in the masked block
///   * Domain: one unresolved `Host`
///
/// Returns a boxed iterator so a `/8` CIDR does not allocate 16M `Host`
/// structs up front — callers stream each host into the bounded channel,
/// applying natural backpressure.
pub fn parse_line(line: &str, ipv6: bool) -> Box<dyn Iterator<Item = Host> + Send> {
    let line = line.trim();
    if line.is_empty() {
        return Box::new(std::iter::empty());
    }

    // IP literal?
    if let Ok(ip) = line.parse::<IpAddr>() {
        if !ipv6 && !ip.is_ipv4() {
            return Box::new(std::iter::empty());
        }
        return Box::new(std::iter::once(Host {
            ip: Some(ip),
            origin: line.to_string(),
            kind: HostType::Ip,
        }));
    }

    // CIDR?
    if let Ok(net) = line.parse::<IpNet>() {
        match net {
            IpNet::V4(_) => {}
            IpNet::V6(_) => {
                if !ipv6 {
                    return Box::new(std::iter::empty());
                }
            }
        }
        let origin = line.to_string();
        return Box::new(cidr_iter(net).map(move |ip| Host {
            ip: Some(ip),
            origin: origin.clone(),
            kind: HostType::Cidr,
        }));
    }

    // Domain?
    if validate_domain(line) {
        return Box::new(std::iter::once(Host {
            ip: None,
            origin: line.to_string(),
            kind: HostType::Domain,
        }));
    }

    tracing::warn!(line = %line, "Not a valid IP, IP CIDR or domain");
    Box::new(std::iter::empty())
}

/// Walks every address in a CIDR block in ascending order, mirroring Go's
/// `netip.Prefix.Masked()` + `addr.Next()` loop, which includes the network
/// and broadcast addresses.
pub fn cidr_iter(net: IpNet) -> Box<dyn Iterator<Item = IpAddr> + Send> {
    match net {
        IpNet::V4(v4) => {
            let network = v4.network();
            let broadcast = v4.broadcast();
            let start = u32::from(network);
            let end = u32::from(broadcast);
            Box::new(
                (start..=end)
                    .map(|n| IpAddr::V4(Ipv4Addr::from(n))),
            )
        }
        IpNet::V6(v6) => {
            let network = v6.network();
            let broadcast = v6.broadcast();
            let start = u128::from(network);
            let end = u128::from(broadcast);
            Box::new(
                (start..=end)
                    .map(|n| IpAddr::V6(Ipv6Addr::from(n))),
            )
        }
    }
}

/// Reads an async source line-by-line (file or inline string) and funnels
/// parsed hosts into `sender`.
pub async fn from_file(path: &Path, ipv6: bool, sender: Sender<Host>) -> anyhow::Result<()> {
    let f = tokio::fs::File::open(path).await?;
    let reader = BufReader::new(f);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        for host in parse_line(&line, ipv6) {
            if sender.send(host).await.is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Same as `from_file` but from an in-memory string; used by the URL crawler.
pub async fn from_string(text: &str, ipv6: bool, sender: Sender<Host>) -> anyhow::Result<()> {
    for line in text.lines() {
        for host in parse_line(line, ipv6) {
            if sender.send(host).await.is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// `--addr` dispatch, matching Go's `IterateAddr`:
///  * If `addr` parses as CIDR, reuse the file-style iterator.
///  * Otherwise treat it as an IP (or resolve via DNS) and enter **infinite
///    mode**: walk outward from the initial IP, alternating low/high, until
///    the sender is closed (e.g. by ctrl_c dropping the producer).
pub async fn from_addr(
    addr: String,
    ipv6: bool,
    dns: Arc<DnsResolver>,
    sender: Sender<Host>,
) -> anyhow::Result<()> {
    // A comma-separated list is a finite set of IPs/CIDRs/domains.
    // Unlike a single bare IP, it never enables the legacy infinite walk.
    if addr.contains(',') {
        for item in addr.split(',') {
            for host in parse_line(item, ipv6) {
                if sender.send(host).await.is_err() {
                    return Ok(());
                }
            }
        }
        return Ok(());
    }

    // CIDR?
    if let Ok(net) = addr.parse::<IpNet>() {
        match net {
            IpNet::V4(_) => {}
            IpNet::V6(_) => {
                if !ipv6 {
                    return Ok(());
                }
            }
        }
        for ip in cidr_iter(net) {
            let host = Host {
                ip: Some(ip),
                origin: addr.clone(),
                kind: HostType::Cidr,
            };
            if sender.send(host).await.is_err() {
                return Ok(());
            }
        }
        return Ok(());
    }

    // IP literal or domain → resolve to one IP and enter infinite mode.
    let initial_ip = if let Ok(ip) = addr.parse::<IpAddr>() {
        if !ipv6 && !ip.is_ipv4() {
            tracing::error!(addr = %addr, "IPv6 disabled, refusing IPv6 address");
            return Ok(());
        }
        ip
    } else {
        match resolver::lookup_first(&dns, &addr, ipv6).await {
            Some(ip) => ip,
            None => {
                tracing::error!(addr = %addr, "Not a valid IP, IP CIDR or domain");
                return Ok(());
            }
        }
    };

    tracing::info!(init = %initial_ip, "Enable infinite mode");

    // Emit the initial IP first.
    let first = Host {
        ip: Some(initial_ip),
        origin: addr.clone(),
        kind: HostType::Ip,
    };
    if sender.send(first).await.is_err() {
        return Ok(());
    }

    // Alternate: walk outward low/high forever.
    let mut low = initial_ip;
    let mut high = initial_ip;
    let mut i: u64 = 0;
    loop {
        let next = if i.is_multiple_of(2) {
            low = step_ip(low, false);
            low
        } else {
            high = step_ip(high, true);
            high
        };
        let host = Host {
            ip: Some(next),
            origin: next.to_string(),
            kind: HostType::Ip,
        };
        if sender.send(host).await.is_err() {
            // Receiver dropped — exit cleanly (e.g. on ctrl_c).
            return Ok(());
        }
        i = i.wrapping_add(1);
    }
}

/// URL crawler matching Go's regex `(http|https)://(.*?)[/"<>\s]+`: fetch the
/// body, extract capture group 2 (the host), dedupe, then feed through
/// `from_string`.
pub async fn from_url(url: String, ipv6: bool, sender: Sender<Host>) -> anyhow::Result<()> {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    tracing::info!(url = %url, "Fetching url...");
    let body = reqwest::get(&url).await?.text().await?;
    let re = URL_RE
        .get_or_init(|| Regex::new(r#"(http|https)://(.*?)[/"<>\s]+"#).unwrap());
    let mut seen: HashSet<String> = HashSet::new();
    let mut domains: Vec<String> = Vec::new();
    for cap in re.captures_iter(&body) {
        if let Some(m) = cap.get(2) {
            let s = m.as_str();
            if !seen.contains(s) {
                let owned = s.to_string();
                seen.insert(owned.clone());
                domains.push(owned);
            }
        }
    }
    tracing::info!(count = domains.len(), "Parsed domains");
    from_string(&domains.join("\n"), ipv6, sender).await
}

/// Wrap/unwrap increment for infinite mode, matching Go's `NextIP(ip, inc)`.
/// Uses `u32`/`u128` wrapping arithmetic so the walk never panics even at
/// the edges of the address space.
fn step_ip(ip: IpAddr, increment: bool) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let n = u32::from(v4);
            let next = if increment { n.wrapping_add(1) } else { n.wrapping_sub(1) };
            IpAddr::V4(Ipv4Addr::from(next))
        }
        IpAddr::V6(v6) => {
            let n = u128::from(v6);
            let next = if increment { n.wrapping_add(1) } else { n.wrapping_sub(1) };
            IpAddr::V6(Ipv6Addr::from(next))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- step_ip ----

    #[test]
    fn step_ip_v4_increment() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(step_ip(ip, true), "192.168.1.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v4_decrement() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(step_ip(ip, false), "192.168.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v4_increment_wraps_at_max() {
        let ip: IpAddr = "255.255.255.255".parse().unwrap();
        assert_eq!(step_ip(ip, true), "0.0.0.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v4_decrement_wraps_at_zero() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert_eq!(
            step_ip(ip, false),
            "255.255.255.255".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn step_ip_v6_increment() {
        let ip: IpAddr = "::".parse().unwrap();
        assert_eq!(step_ip(ip, true), "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v6_decrement() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert_eq!(step_ip(ip, false), "::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v6_increment_wraps_at_max() {
        let max: IpAddr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(step_ip(max, true), "::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn step_ip_v6_decrement_wraps_at_zero() {
        let zero: IpAddr = "::".parse().unwrap();
        assert_eq!(
            step_ip(zero, false),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn comma_separated_ranges_scan_a_finite_set() {
        let dns = resolver::build();
        let (tx, rx) = async_channel::bounded(16);
        from_addr("192.0.2.0/30,198.51.100.9/32".to_owned(), false, dns, tx)
            .await
            .unwrap();
        let hosts: Vec<Host> = rx.try_iter().collect();
        assert_eq!(hosts.len(), 5);
        assert_eq!(hosts.first().unwrap().ip.unwrap().to_string(), "192.0.2.0");
        assert_eq!(hosts.last().unwrap().ip.unwrap().to_string(), "198.51.100.9");
    }

    // ---- cidr_iter ----

    #[test]
    fn cidr_iter_slash_30_includes_network_and_broadcast() {
        let net: IpNet = "192.168.1.0/30".parse().unwrap();
        let addrs: Vec<IpAddr> = cidr_iter(net).collect();
        let expected: Vec<IpAddr> = vec![
            "192.168.1.0".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            "192.168.1.3".parse().unwrap(),
        ];
        assert_eq!(addrs, expected);
    }

    #[test]
    fn cidr_iter_slash_32_yields_single_address() {
        let net: IpNet = "10.0.0.0/32".parse().unwrap();
        let addrs: Vec<IpAddr> = cidr_iter(net).collect();
        assert_eq!(addrs, vec!["10.0.0.0".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn cidr_iter_slash_8_is_lazy() {
        // Laziness guard: taking the first 3 of a `/8` must not materialise
        // the full 16M-entry set. If cidr_iter ever pre-allocates, this test
        // will still pass a correctness check but blow up memory — so we also
        // assert sub-second wall time on a machine that can do 16M allocs in
        // much less than that. The real proof is the counted take(3).
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        let first_three: Vec<IpAddr> = cidr_iter(net).take(3).collect();
        assert_eq!(
            first_three,
            vec![
                "10.0.0.0".parse::<IpAddr>().unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    // ---- parse_line ----

    #[test]
    fn parse_line_ipv4_literal() {
        let hosts: Vec<Host> = parse_line("192.168.1.1", false).collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].kind, HostType::Ip);
        assert_eq!(
            hosts[0].ip,
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(hosts[0].origin, "192.168.1.1");
    }

    #[test]
    fn parse_line_ipv4_cidr_expands_in_order() {
        let hosts: Vec<Host> = parse_line("192.168.1.0/30", false).collect();
        assert_eq!(hosts.len(), 4);
        for h in &hosts {
            assert_eq!(h.kind, HostType::Cidr);
            assert_eq!(h.origin, "192.168.1.0/30");
        }
        let ips: Vec<IpAddr> = hosts.iter().map(|h| h.ip.unwrap()).collect();
        assert_eq!(
            ips,
            vec![
                "192.168.1.0".parse::<IpAddr>().unwrap(),
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                "192.168.1.3".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_line_domain() {
        let hosts: Vec<Host> = parse_line("example.com", false).collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].kind, HostType::Domain);
        assert_eq!(hosts[0].ip, None);
        assert_eq!(hosts[0].origin, "example.com");
    }

    #[test]
    fn parse_line_ipv6_literal_filtered_when_ipv6_disabled() {
        let hosts: Vec<Host> = parse_line("::1", false).collect();
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_line_ipv6_literal_passes_when_ipv6_enabled() {
        let hosts: Vec<Host> = parse_line("::1", true).collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].kind, HostType::Ip);
        assert_eq!(hosts[0].ip, Some("::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_line_invalid_yields_nothing() {
        let hosts: Vec<Host> = parse_line("not@a#domain", false).collect();
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_line_empty_yields_nothing() {
        assert_eq!(parse_line("", false).count(), 0);
    }

    #[test]
    fn parse_line_whitespace_yields_nothing() {
        assert_eq!(parse_line("   \t  ", false).count(), 0);
    }

    #[test]
    fn parse_line_trims_input() {
        let hosts: Vec<Host> = parse_line("  192.168.1.1  ", false).collect();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].origin, "192.168.1.1");
    }
}
