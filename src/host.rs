use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostType {
    Ip,
    Cidr,
    Domain,
}

#[derive(Clone, Debug)]
pub struct Host {
    /// Resolved IP address. `None` for a raw Domain until DNS is performed.
    pub ip: Option<IpAddr>,
    /// The original user-supplied line (or the CIDR that produced this host).
    pub origin: String,
    pub kind: HostType,
}

/// Matches Go's `^[A-Za-z0-9\-.]+$`.
pub fn validate_domain(s: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9\-.]+$").unwrap())
        .is_match(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_domain_accepts_example_com() {
        assert!(validate_domain("example.com"));
    }

    #[test]
    fn validate_domain_accepts_subdomain_with_hyphen() {
        assert!(validate_domain("sub.example-site.io"));
    }

    #[test]
    fn validate_domain_accepts_ipv4_literal() {
        // The Go regex matches digits + dots, so a bare IPv4 literal passes.
        // That's fine: parse_line tries IP parsing first, so this branch is
        // never reached for a real IP — the test just pins the regex shape.
        assert!(validate_domain("192.168.1.1"));
    }

    #[test]
    fn validate_domain_rejects_empty() {
        assert!(!validate_domain(""));
    }

    #[test]
    fn validate_domain_rejects_whitespace() {
        assert!(!validate_domain("has space"));
    }

    #[test]
    fn validate_domain_rejects_underscore() {
        // Underscore is not in `[A-Za-z0-9\-.]`.
        assert!(!validate_domain("under_score.com"));
    }

    #[test]
    fn validate_domain_rejects_slash() {
        assert!(!validate_domain("weird/path"));
    }

    #[test]
    fn host_type_is_copy_and_eq() {
        let a = HostType::Ip;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(HostType::Ip, HostType::Cidr);
        assert_ne!(HostType::Ip, HostType::Domain);
    }
}
