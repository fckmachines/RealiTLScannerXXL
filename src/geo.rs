use std::net::IpAddr;
use std::path::Path;

pub struct Geo {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl Geo {
    pub fn load(path: &Path) -> Self {
        match maxminddb::Reader::open_readfile(path) {
            Ok(r) => {
                tracing::info!(path = %path.display(), "GeoIP enabled");
                Self { reader: Some(r) }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "GeoIP disabled");
                Self { reader: None }
            }
        }
    }

    pub fn country_code(&self, ip: IpAddr) -> String {
        let Some(reader) = &self.reader else {
            return "N/A".to_string();
        };
        match reader.lookup::<maxminddb::geoip2::Country>(ip) {
            Ok(c) => c
                .country
                .and_then(|c| c.iso_code)
                .unwrap_or("N/A")
                .to_string(),
            Err(_) => "N/A".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_mmdb_returns_na_for_any_ip() {
        let geo = Geo::load(Path::new("this-file-does-not-exist.mmdb"));
        assert!(geo.reader.is_none());
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert_eq!(geo.country_code(v4), "N/A");
        assert_eq!(geo.country_code(v6), "N/A");
    }

    #[test]
    fn missing_mmdb_returns_na_for_private_ip() {
        // Mirrors Go's graceful-degradation behavior: even for addresses that
        // have no sensible country answer, we return "N/A" rather than erroring.
        let geo = Geo::load(Path::new("definitely/not/here.mmdb"));
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(geo.country_code(ip), "N/A");
    }
}
