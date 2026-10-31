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
    let head = body.get(..16_384).unwrap_or(body);
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

/// Verify the actual scanned IP, not merely the public DNS destination of
/// the certificate CN. reqwest's `resolve` pins the HTTPS connection to `ip`,
/// while the URL still supplies the original hostname for SNI, Host, and
/// certificate hostname validation. Redirects are deliberately NOT followed:
/// doing so could leave the scanned IP and invalidate the result.
/// A new client per candidate keeps DNS overrides isolated across concurrent
/// probes. Body reading is bounded to 16 KiB.
pub async fn check_http(cn: &str, ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .resolve(cn, std::net::SocketAddr::new(ip, port))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(%ip, %cn, error = %e, "http client init failed");
            return false;
        }
    };
    let url = format!("https://{cn}:{port}/");
    let response = client.get(url).send().await;
    let mut response = match response {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(%ip, %cn, error = %e, "IP-pinned HTTPS request failed");
            return false;
        }
    };
    let status = response.status().as_u16();
    if !matches!(status, 200 | 301 | 302) {
        tracing::debug!(%ip, %cn, status, "IP-pinned HTTPS status rejected");
        return false;
    }

    let mut body = Vec::with_capacity(16_384);
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = (16_384 - body.len()).min(chunk.len());
                body.extend_from_slice(&chunk[..take]);
                if body.len() == 16_384 {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(%ip, %cn, error = %e, "IP-pinned HTTPS body failed");
                return false;
            }
        }
    }
    let text = String::from_utf8_lossy(&body);
    !is_parked_page(&text)
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
    fn parked_page_handles_multibyte_utf8_boundary() {
        let input = format!("{}🛰️", "a".repeat(16_383));
        assert!(!is_parked_page(&input));
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
