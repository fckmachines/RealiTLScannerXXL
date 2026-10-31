//! IPv4 egress identity and RIPEstat lookups.
//! This module queries external services only when the interactive UI or
//! an explicit ASN scan requests it; no source IP is guessed from local NAT.
use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde_json::Value;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

const RIPESTAT: &str = "https://stat.ripe.net/data";

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .user_agent("RealiTLScannerXXL/0.4 (network discovery)")
        .build()?)
}

#[derive(Debug, Default)]
pub struct Identity {
    pub ip: Option<Ipv4Addr>,
    pub prefix: Option<String>,
    pub asns: Vec<u32>,
    pub holder: Option<String>,
}

impl Identity {
    pub fn display(&self) {
        println!("   IPv4 (исходящий): {}", self.ip.map(|x| x.to_string()).unwrap_or_else(|| "не определён".into()));
        let asns = if self.asns.is_empty() {
            "не определён".to_string()
        } else {
            self.asns.iter().map(|n| format!("AS{n}")).collect::<Vec<_>>().join(", ")
        };
        println!("   ASN (RIPE RIS):   {asns}");
        if let Some(holder) = &self.holder {
            println!("   Сеть:             {holder}");
        }
        if let Some(prefix) = &self.prefix {
            println!("   BGP-префикс:      {prefix}");
        }
        println!();
    }
}

/// External IPv4 egress address; this can differ from a private VPS interface.
pub async fn discover() -> Identity {
    let mut result = Identity::default();
    let Ok(client) = client() else { return result };

    for endpoint in ["https://api4.ipify.org", "https://ipv4.icanhazip.com"] {
        if let Ok(Ok(response)) = tokio::time::timeout(
            Duration::from_secs(4), client.get(endpoint).send()
        ).await {
            if let Ok(Ok(body)) = tokio::time::timeout(
                Duration::from_secs(3), response.error_for_status().and_then(|r| Ok(r)).unwrap_or_else(|_| unreachable!()).text()
            ).await {
                if let Ok(ip) = body.trim().parse::<Ipv4Addr>() {
                    result.ip = Some(ip);
                    break;
                }
            }
        }
    }
    if let Some(ip) = result.ip {
        let query = [("resource", ip.to_string())];
        if let Ok(response) = client.get(format!("{RIPESTAT}/network-info/data.json"))
            .query(&query).send().await {
            if let Ok(response) = response.error_for_status() {
                if let Ok(json) = response.json::<Value>().await {
                    let (asns, prefix) = parse_network_info(&json);
                    result.asns = asns;
                    result.prefix = prefix;
                }
            }
        }
        if let Some(asn) = result.asns.first().copied() {
            let query = [("resource", format!("AS{asn}"))];
            if let Ok(response) = client.get(format!("{RIPESTAT}/as-overview/data.json"))
                .query(&query).send().await {
                if let Ok(response) = response.error_for_status() {
                    if let Ok(json) = response.json::<Value>().await {
                        result.holder = json.pointer("/data/holder").and_then(Value::as_str)
                            .map(str::to_string).filter(|s| !s.is_empty());
                    }
                }
            }
        }
    }
    result
}

fn parse_network_info(json: &Value) -> (Vec<u32>, Option<String>) {
    let asns = json.pointer("/data/asns").and_then(Value::as_array)
        .map(|values| values.iter().filter_map(|x| {
            x.as_u64().and_then(|n| u32::try_from(n).ok())
                .or_else(|| x.as_str().and_then(|s| s.parse::<u32>().ok()))
        }).collect())
        .unwrap_or_default();
    let prefix = json.pointer("/data/prefix").and_then(Value::as_str).map(str::to_string);
    (asns, prefix)
}

pub fn parse_asn(value: &str) -> Result<u32> {
    let s = value.trim();
    let digits = s.strip_prefix("AS").or_else(|| s.strip_prefix("as")).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Неверный ASN: укажите AS12345 либо 12345");
    }
    let n = digits.parse::<u32>().context("ASN выходит за пределы 32 бит")?;
    if n == 0 {
        bail!("ASN должен быть больше нуля");
    }
    Ok(n)
}

pub async fn prefixes(asn: &str, max_ips: u64) -> Result<Vec<Ipv4Net>> {
    let asn = parse_asn(asn)?;
    let client = client()?;
    let json: Value = client.get(format!("{RIPESTAT}/announced-prefixes/data.json"))
        .query(&[("resource", format!("AS{asn}"))])
        .send().await.context("RIPEstat недоступен")?
        .error_for_status().context("Ошибка RIPEstat")?
        .json().await.context("Некорректный ответ RIPEstat")?;
    parse_prefixes(&json, max_ips).context(format!("AS{asn}"))
}

/// Fail closed if the ASN's observed IPv4 address space exceeds the configured
/// cap. Never silently truncate the network: the user can raise --max-ips.
fn parse_prefixes(json: &Value, max_ips: u64) -> Result<Vec<Ipv4Net>> {
    let items = json.pointer("/data/prefixes").and_then(Value::as_array)
        .context("В ответе RIPEstat отсутствует список префиксов")?;
    let mut seen = HashSet::new();
    let mut networks = Vec::new();
    let mut count = 0u64;
    for item in items {
        let Some(value) = item.get("prefix").and_then(Value::as_str) else { continue };
        let Ok(net) = value.parse::<Ipv4Net>() else { continue };
        let net = net.trunc();
        if !seen.insert(net) { continue }
        count = count.checked_add(1u64 << (32 - net.prefix_len()))
            .context("Слишком много IPv4-адресов")?;
        if count > max_ips {
            bail!("AS содержит не менее {count} IPv4-адресов (лимит {max_ips}). Увеличьте --max-ips после оценки масштаба.");
        }
        networks.push(net);
    }
    if networks.is_empty() {
        bail!("Не найдено анонсируемых IPv4-префиксов");
    }
    networks.sort_by_key(|n| (u32::from(n.network()), n.prefix_len()));
    Ok(networks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_network_identity() {
        let data = json!({"data":{"asns":[16509,14618],"prefix":"203.0.113.0/24"}});
        let (asns, prefix) = parse_network_info(&data);
        assert_eq!(asns, vec![16509,14618]);
        assert_eq!(prefix.as_deref(), Some("203.0.113.0/24"));
    }
    #[test]
    fn validates_asn() {
        assert_eq!(parse_asn("AS3333").unwrap(), 3333);
        assert_eq!(parse_asn("3333").unwrap(), 3333);
        assert!(parse_asn("AS0").is_err());
        assert!(parse_asn("AS33;exit").is_err());
    }
    #[test]
    fn prefix_limit_and_dedupe() {
        let data = json!({"data":{"prefixes":[{"prefix":"192.0.2.0/24"},{"prefix":"192.0.2.0/24"},{"prefix":"2001:db8::/32"}]}});
        assert_eq!(parse_prefixes(&data, 256).unwrap().len(), 1);
        assert!(parse_prefixes(&data, 255).is_err());
    }
}
