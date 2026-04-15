use clap::{ArgGroup, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "realitlscanner", version, about = "Reality-TLS scanner")]
#[command(group(ArgGroup::new("source").required(true).args(["addr", "input", "url"])))]
pub struct Cli {
    /// IP, CIDR, or domain to scan
    #[arg(long)]
    pub addr: Option<String>,

    /// File with targets, one per line
    #[arg(long = "in", value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// URL to crawl for domains
    #[arg(long)]
    pub url: Option<String>,

    #[arg(long, default_value_t = 443)]
    pub port: u16,

    /// Concurrent probe tasks
    #[arg(long, default_value_t = 2)]
    pub thread: usize,

    /// Output CSV (empty disables file)
    #[arg(long, default_value = "out.csv")]
    pub out: String,

    #[arg(long, default_value_t = 10)]
    pub timeout: u64,

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

    /// HTTP GET `/` probe after a feasible TLS handshake: require
    /// 200/301/302 and a non-parked body. Automatically enabled when
    /// `--reality-sni` is set.
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
    fn custom_port_parses() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1", "--port", "8443"]).unwrap();
        assert_eq!(cli.port, 8443);
    }

    #[test]
    fn defaults_match_go_version() {
        let cli = Cli::try_parse_from(["x", "--addr", "1.1.1.1"]).unwrap();
        assert_eq!(cli.port, 443);
        assert_eq!(cli.thread, 2);
        assert_eq!(cli.timeout, 10);
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
