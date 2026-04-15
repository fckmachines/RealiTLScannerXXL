//! Reality-SNI post-probe filters. When `--reality-sni` is on, a feasible
//! host additionally has to pass every check here to land in the output.
//! `--exclude-geo` and `--check-http` are independent filters that can be
//! used with or without `--reality-sni`.

use crate::resolver::DnsResolver;
use std::net::IpAddr;
use std::time::Duration;

/// Suffix blocklist for shared / CDN certificates that are unsuitable as
/// Reality SNI: the cert is served for many unrelated sites, so using it as
/// `dest` gives no real cover. Matching is a plain `ends_with` against the
/// CN, which catches both bare suffixes and `*.suffix` wildcards.
const SHARED_CDN_SUFFIXES: &[&str] = &[
    // Cloudflare shared/edge
    "cloudflaressl.com",
    "cdn.cloudflare.net",
    // Akamai
    "akamaiedge.net",
    "akamaihd.net",
    "akamaized.net",
    "edgekey.net",
    "edgesuite.net",
    // Amazon
    "cloudfront.net",
    "amazonaws.com",
    // Microsoft
    "azureedge.net",
    "azurefd.net",
    "azurewebsites.net",
    // Fastly
    "fastly.net",
    "fastlylb.net",
    // Google
    "googleusercontent.com",
    "appspot.com",
    // Misc CDN / PaaS
    "cdn77.org",
    "incapdns.net",
    "b-cdn.net",
    "kxcdn.com",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "github.io",
];

/// Parked-page markers — case-insensitive substring match. Deliberately
/// conservative: each entry is a phrase that basically never appears on real
/// sites but is boilerplate on domain-parking / for-sale landers.
const PARKED_MARKERS: &[&str] = &[
    "domain is for sale",
    "buy this domain",
    "this domain is parked",
    "parked domain",
    "domain parking",
    "domain has expired",
    "hugedomains.com",
    "sedoparking.com",
    "parkingcrew.net",
    "bodis.com",
    "dan.com/buy-domain",
    "afternic.com",
    "undeveloped.com",
    "godaddy.com/domainsearch",
];

/// A cert with a wildcard CN cannot be used as SNI literally — the client
/// needs a concrete hostname under the wildcard, which the scanner does not
/// discover.
pub fn is_wildcard_cn(cn: &str) -> bool {
    cn.starts_with("*.")
}

/// True if the CN ends with any known shared-CDN suffix.
pub fn is_shared_cdn_cn(cn: &str) -> bool {
    SHARED_CDN_SUFFIXES
        .iter()
        .any(|suffix| cn.ends_with(suffix))
}

/// True if the geo code appears in the caller-supplied exclusion list. Empty
/// list = nothing excluded. Case-insensitive comparison so the CLI accepts
/// `ru,cn` as well as `RU,CN`.
pub fn is_excluded_geo(geo: &str, exclude_list: &[String]) -> bool {
    exclude_list
        .iter()
        .any(|code| code.eq_ignore_ascii_case(geo))
}

/// True if the HTTP body looks like a parked-domain lander. First ~16 KiB
/// is enough — parking providers put their branding in the `<head>` or the
/// top of the `<body>`.
pub fn is_parked_page(body: &str) -> bool {
    let head = &body[..body.len().min(16_384)];
    let lower = head.to_ascii_lowercase();
    PARKED_MARKERS.iter().any(|m| lower.contains(m))
}

/// Forward-verify: the cert CN must resolve via DNS to include the probed
/// IP. This rejects accidental matches (e.g. a shared-hosting IP serving a
/// cert for an unrelated domain) at the cost of occasionally dropping
/// CDN-fronted sites whose anycast returns different IPs per query.
pub async fn forward_verify(dns: &DnsResolver, cn: &str, expected: IpAddr) -> bool {
    match dns.lookup_ip(cn).await {
        Ok(response) => response.iter().any(|ip| ip == expected),
        Err(_) => false,
    }
}

/// HTTP GET `https://{cn}/` and require a 200/301/302 with a non-parked
/// body. Uses a shared `reqwest::Client` (one per process, Arc-wrapped).
/// Redirect following is enabled (up to 3 hops) so `301 → 200` is treated
/// as the final 200.
pub async fn check_http(client: &reqwest::Client, cn: &str, timeout: Duration) -> bool {
    let url = format!("https://{}/", cn);
    let req = client.get(&url).timeout(timeout);
    let resp = match req.send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let status = resp.status().as_u16();
    if !matches!(status, 200 | 301 | 302) {
        return false;
    }
    match resp.text().await {
        Ok(body) => !is_parked_page(&body),
        // Good status but unreadable body — trust the status line.
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_cn_rejected() {
        assert!(is_wildcard_cn("*.example.com"));
        assert!(is_wildcard_cn("*.grupoandrea.com"));
        assert!(!is_wildcard_cn("example.com"));
        assert!(!is_wildcard_cn("www.example.com"));
        assert!(!is_wildcard_cn(""));
    }

    #[test]
    fn shared_cdn_cn_rejected() {
        // Cloudflare shared SSL
        assert!(is_shared_cdn_cn("ssl866443.cloudflaressl.com"));
        // AWS / CloudFront
        assert!(is_shared_cdn_cn("d1234abcd.cloudfront.net"));
        assert!(is_shared_cdn_cn("my-bucket.s3.amazonaws.com"));
        // Azure
        assert!(is_shared_cdn_cn("myapp.azureedge.net"));
        assert!(is_shared_cdn_cn("myapp.azurewebsites.net"));
        // PaaS
        assert!(is_shared_cdn_cn("myapp.herokuapp.com"));
        assert!(is_shared_cdn_cn("project-foo.vercel.app"));
        assert!(is_shared_cdn_cn("mysite.netlify.app"));
        assert!(is_shared_cdn_cn("user.github.io"));
        // Legit domains should pass
        assert!(!is_shared_cdn_cn("brainly.com"));
        assert!(!is_shared_cdn_cn("www.microsoft.com"));
        assert!(!is_shared_cdn_cn("example.org"));
    }

    #[test]
    fn shared_cdn_matches_wildcard_form() {
        // Wildcard CNs ending in a CDN suffix should also be caught — the
        // `ends_with` rule covers both bare and wildcarded forms.
        assert!(is_shared_cdn_cn("*.cloudfront.net"));
        assert!(is_shared_cdn_cn("*.azureedge.net"));
    }

    #[test]
    fn excluded_geo_matches_list() {
        let list = vec!["RU".to_string(), "CN".to_string(), "IR".to_string()];
        assert!(is_excluded_geo("RU", &list));
        assert!(is_excluded_geo("CN", &list));
        assert!(is_excluded_geo("IR", &list));
    }

    #[test]
    fn excluded_geo_is_case_insensitive() {
        // The CLI may receive either `--exclude-geo ru,cn` or `RU,CN`.
        let upper = vec!["RU".to_string()];
        assert!(is_excluded_geo("ru", &upper));
        let lower = vec!["ru".to_string()];
        assert!(is_excluded_geo("RU", &lower));
    }

    #[test]
    fn excluded_geo_empty_list_matches_nothing() {
        assert!(!is_excluded_geo("RU", &[]));
        assert!(!is_excluded_geo("N/A", &[]));
        assert!(!is_excluded_geo("", &[]));
    }

    #[test]
    fn excluded_geo_skips_other_codes() {
        let list = vec!["RU".to_string(), "CN".to_string()];
        assert!(!is_excluded_geo("US", &list));
        assert!(!is_excluded_geo("DE", &list));
        assert!(!is_excluded_geo("JP", &list));
        assert!(!is_excluded_geo("N/A", &list));
        assert!(!is_excluded_geo("", &list));
    }

    #[test]
    fn parked_page_detects_for_sale() {
        assert!(is_parked_page("This domain is for sale, inquire now"));
        assert!(is_parked_page("<html>Buy this domain</html>"));
        assert!(is_parked_page("Welcome to domain parking provider"));
    }

    #[test]
    fn parked_page_detects_provider_branding() {
        assert!(is_parked_page(
            "<a href=\"https://hugedomains.com/buy\">Buy</a>"
        ));
        assert!(is_parked_page("Powered by sedoparking.com"));
        assert!(is_parked_page("parkingcrew.net hosted"));
    }

    #[test]
    fn parked_page_is_case_insensitive() {
        assert!(is_parked_page("DOMAIN IS FOR SALE"));
        assert!(is_parked_page("This Domain Is Parked"));
    }

    #[test]
    fn parked_page_passes_real_content() {
        assert!(!is_parked_page(
            "<html><body>Welcome to our store. Products, pricing, cart.</body></html>"
        ));
        assert!(!is_parked_page("Microsoft Corporation - Official Home Page"));
        assert!(!is_parked_page(""));
        // A real e-commerce page may mention selling products without
        // tripping the "domain is for sale" phrase.
        assert!(!is_parked_page(
            "Our products are on sale this week. Shop now!"
        ));
    }
}
