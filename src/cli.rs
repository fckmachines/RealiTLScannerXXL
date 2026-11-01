use clap::{ArgGroup, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "realitlscanner", version, about = "Reality-TLS scanner")]
#[command(group(ArgGroup::new("source").required(true).args(["addr", "input", "url", "asn"])))]
pub struct Cli {
    /// IP, CIDR, domain, or comma-separated finite list of targets
    #[arg(long)]
    pub addr: Option<String>,

    /// File with targets, one per line
    #[arg(long = "in", value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// URL to crawl for domains
    #[arg(long)]
    pub url: Option<String>,

    /// Fetch observed announced IPv4 prefixes for this ASN from RIPEstat
    #[arg(long, value_name = "ASN")]
    pub asn: Option<String>,

    /// Maximum number of unique IPv4 targets sampled across an ASN
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_ips: u64,

    /// Scan the entire RIPEstat-observed ASN IPv4 space (no partial cap)
    #[arg(long, requires = "asn", conflicts_with_all = ["addr", "input", "url"])]
    pub all: bool,

    /// Suppress external public-IP/ASN lookup in the interactive banner
    #[arg(long)]
    pub no_network_info: bool,

    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// FAST SCAN: Masscan SYN discovery then Rust/Tokio DEEP SCAN
    #[arg(long, conflicts_with = "url")]
    pub fast: bool,

    /// Masscan maximum packet rate (packets/second); set conservatively for VPS
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=100000))]
    pub fast_rate: u32,

    /// Seconds to wait for SYN responses after Masscan finishes sending
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(1..=60))]
    pub fast_wait: u32,

    /// Global rate limit for STARTING DEEP TCP/TLS probes, per second
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub deep_rate: u32,

    /// Concurrent probe tasks
    #[arg(long, default_value_t = 32)]
    pub thread: usize,

    /// Output CSV (empty disables file)
    #[arg(long, default_value = "out.csv")]
    pub out: String,

    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

    /// Maximum certificate domain (CN) length in Unicode characters; 0 disables the filter
    #[arg(long, default_value_t = 20, value_name = "CHARS")]
    pub max_domain_length: usize,

    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Enable IPv6 as well as IPv4
    #[arg(long = "46", default_value_t = false)]
    pub ipv6: bool,

    /// Also print feasible cert domains to stdout, one per line
    #[arg(long, default_value_t = false)]
    pub domains_only: bool,

    /// Reality SNI filter: reject wildcard CNs, shared-CDN certs, and
    /// require the cert CN to forward-resolve to the probed IP. Implies
    /// `--check-http`. Combine with `--exclude-geo RU,CN` for geo filtering.
    #[arg(long, default_value_t = false)]
    pub reality_sni: bool,

    /// Comma-separated ISO country codes to exclude (e.g. `RU,CN,IR`).
    /// Empty = no geo filter. Works with or without `--reality-sni`.
    #[arg(long, value_delimiter = ',')]
    pub exclude_geo: Vec<String>,

    /// IP-pinned HTTPS GET / (CN as SNI/Host, no redirect following).
    /// Requires 200/301/302 and a non-parked body. Implied by --reality-sni.
    #[arg(long, default_value_t = false)]
    pub check_http: bool,

    /// Path to MaxMind Country DB
    #[arg(long, default_value = "Country.mmdb")]
    pub mmdb: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_addr_invocation() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1"]).expect("should parse");
        assert_eq!(cli.addr.as_deref(), Some("1.1.1.1"));
        assert!(cli.input.is_none());
        assert!(cli.url.is_none());
        assert!(cli.asn.is_none());
    }

    #[test]
    fn missing_source_group_is_error() {
        let res = Cli::try_parse_from(["x"]);
        assert!(res.is_err(), "source group should be required");
    }

    #[test]
    fn addr_and_input_are_mutually_exclusive() {
        let res = Cli::try_parse_from(["x", "--addr", "a", "--in", "b"]);
        assert!(
            res.is_err(),
            "--addr and --in should not both be allowed"
        );
    }

    #[test]
    fn addr_and_url_are_mutually_exclusive() {
        let res = Cli::try_parse_from(["x", "--addr", "a", "--url", "http://x"]);
        assert!(
            res.is_err(),
            "--addr and --url should not both be allowed"
        );
    }

    #[test]
    fn comma_separated_ranges_parse_as_one_source() {
        let cli = Cli::try_parse_from([
            "x", "--addr", "192.0.2.0/24,198.51.100.0/24"
        ]).unwrap();
        assert_eq!(cli.addr.as_deref(), Some("192.0.2.0/24,198.51.100.0/24"));
    }

    #[test]
    fn asn_source_parses() {
        let cli = Cli::try_parse_from(["x", "--asn", "AS3333"]).unwrap();
        assert_eq!(cli.asn.as_deref(), Some("AS3333"));
        assert_eq!(cli.max_ips, 4096);
        assert!(!cli.all);
    }

    #[test]
    fn full_asn_scan_is_explicit() {
        let cli = Cli::try_parse_from(["x", "--asn", "AS14618", "--all"]).unwrap();
        assert!(cli.all);
        assert!(Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--all"]).is_err());
    }

    #[test]
    fn asn_and_addr_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["x", "--asn", "AS3333", "--addr", "1.1.1.1"]).is_err());
    }

    #[test]
    fn fast_cli_settings() {
        let cli = Cli::try_parse_from(["x","--asn","AS14618","--fast",
            "--fast-rate","2500","--fast-wait","8"]).unwrap();
        assert!(cli.fast);
        assert_eq!(cli.fast_rate,2500);
        assert_eq!(cli.fast_wait,8);
        assert!(Cli::try_parse_from(["x","--url","https://example.com","--fast"]).is_err());
        assert!(Cli::try_parse_from(["x","--addr","192.0.2.0/24","--fast-rate","0"]).is_err());
    }

    #[test]
    fn deep_rate_is_bounded_and_configurable() {
        let x = Cli::try_parse_from([
            "x", "--addr", "192.0.2.1/32", "--deep-rate", "7",
        ]).unwrap();
        assert_eq!(x.deep_rate, 7);
        for invalid in ["0", "1001", "garbage"] {
            assert!(Cli::try_parse_from([
                "x", "--addr", "192.0.2.1/32", "--deep-rate", invalid,
            ]).is_err());
        }
    }

    #[test]
    fn domain_length_limit_parsing() {
        let default = Cli::try_parse_from(["x", "--addr", "192.0.2.0/32"]).unwrap();
        assert_eq!(default.max_domain_length, 20);
        let custom = Cli::try_parse_from([
            "x", "--addr", "192.0.2.0/32", "--max-domain-length", "24",
        ]).unwrap();
        assert_eq!(custom.max_domain_length, 24);
        let disabled = Cli::try_parse_from([
            "x", "--addr", "192.0.2.0/32", "--max-domain-length", "0",
        ]).unwrap();
        assert_eq!(disabled.max_domain_length, 0);
        assert!(Cli::try_parse_from([
            "x", "--addr", "192.0.2.0/32", "--max-domain-length", "nope",
        ]).is_err());
    }

    #[test]
    fn custom_port_parses() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--port", "8443"]).unwrap();
        assert_eq!(cli.port, 8443);
    }

    #[test]
    fn defaults_match_go_version() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1"]).unwrap();
        assert_eq!(cli.port, 443);
        assert_eq!(cli.thread, 32);
        assert_eq!(cli.timeout, 10);
        assert_eq!(cli.max_domain_length, 20);
        assert!(!cli.fast);
        assert_eq!(cli.fast_rate, 100);
        assert_eq!(cli.deep_rate, 10);
        assert_eq!(cli.fast_wait, 5);
        assert_eq!(cli.out, "out.csv");
        assert_eq!(cli.mmdb, PathBuf::from("Country.mmdb"));
        assert!(!cli.verbose);
        assert!(!cli.ipv6);
        assert!(!cli.domains_only);
        assert!(!cli.reality_sni);
        assert!(!cli.check_http);
        assert!(cli.exclude_geo.is_empty());
    }

    #[test]
    fn reality_sni_flag_parses() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--reality-sni"]).unwrap();
        assert!(cli.reality_sni);
    }

    #[test]
    fn exclude_geo_parses_comma_list() {
        let cli =
            Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--exclude-geo", "RU,CN,IR"])
                .unwrap();
        assert_eq!(cli.exclude_geo, vec!["RU", "CN", "IR"]);
    }

    #[test]
    fn exclude_geo_single_code_parses() {
        let cli =
            Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--exclude-geo", "RU"]).unwrap();
        assert_eq!(cli.exclude_geo, vec!["RU"]);
    }

    #[test]
    fn check_http_flag_parses() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--check-http"]).unwrap();
        assert!(cli.check_http);
    }

    #[test]
    fn ipv6_flag_is_46() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--46"]).unwrap();
        assert!(cli.ipv6);
    }

    #[test]
    fn url_source_parses() {
        let cli = Cli::try_parse_from(["x", "--url", "https://example.com"]).unwrap();
        assert_eq!(cli.url.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn input_source_parses() {
        let cli = Cli::try_parse_from(["x", "--in", "targets.txt"]).unwrap();
        assert_eq!(cli.input, Some(PathBuf::from("targets.txt")));
    }
}
