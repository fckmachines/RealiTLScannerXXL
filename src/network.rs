//! IPv4 egress identity and RIPEstat lookups.
//! This module queries external services only when the interactive UI or
//! an explicit ASN scan requests it; no source IP is guessed from local NAT.
use anyhow::{bail, Context, Result};
use ipnet::Ipv4Net;
use serde_json::Value;
use std::net::Ipv4Addr;
use std::time::Duration;

const RIPESTAT: &str = "https://stat.ripe.net/data";

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .user_agent("RealiTLScannerXXL/0.4.1 (network discovery)")
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
        if let Ok(response) = client.get(endpoint).send().await {
            if let Ok(response) = response.error_for_status() {
                if let Ok(body) = response.text().await {
                    if let Ok(ip) = body.trim().parse::<Ipv4Addr>() {
                        result.ip = Some(ip);
                        break;
                    }
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

/// One disjoint, ascending inclusive interval. The offset is the start
/// index in the concatenated address space of all disjoint intervals.
#[derive(Clone, Debug)]
struct Range {
    start: u32,
    end: u32,
    offset: u64,
}

#[derive(Clone, Debug)]
pub struct ScanPlan {
    pub asn: u32,
    pub holder: Option<String>,
    pub observed_prefixes: usize,
    pub total: u64,
    ranges: Vec<Range>,
}

impl ScanPlan {
    pub fn selected(&self, maximum: u64, all: bool) -> u64 {
        if all { self.total } else { self.total.min(maximum) }
    }

    /// Deterministic evenly-spaced selection over *unique* announced IPv4
    /// addresses. Uses u128 arithmetic, does not allocate per-target IPs,
    /// and is strictly increasing when `selected <= self.total`.
    pub fn address_at(&self, i: u64, selected: u64) -> Ipv4Addr {
        assert!(selected > 0 && selected <= self.total && i < selected);
        let rank = (((i as u128) * 2 + 1) * self.total as u128
            / (2 * selected as u128)) as u64;
        let index = self.ranges.partition_point(|range| range.offset <= rank) - 1;
        let range = &self.ranges[index];
        Ipv4Addr::from(range.start + (rank - range.offset) as u32)
    }

    pub fn preview(&self, selected: u64) -> String {
        let scope = if selected < self.total { "ЧАСТИЧНАЯ ВЫБОРКА" } else { "ВСЕ АДРЕСА" };
        format!(
            "ASN: AS{}{}\nIPv4-префиксов (наблюдалось): {}\nУникальных IPv4: {}\nБудет проверено: {} из {} ({})",
            self.asn,
            self.holder.as_ref().map(|name| format!(" — {name}")).unwrap_or_default(),
            self.observed_prefixes, self.total, selected, self.total, scope
        )
    }
}

/// RIPEstat gives an observation-window view, not a proof of current routing.
/// Fetch it exactly once and keep the normalized immutable scan plan.
pub async fn fetch_plan(asn: &str) -> Result<ScanPlan> {
    let asn = parse_asn(asn)?;
    let client = client()?;
    let json: Value = client.get(format!("{RIPESTAT}/announced-prefixes/data.json"))
        .query(&[("resource", format!("AS{asn}"))])
        .timeout(Duration::from_secs(25))
        .send().await.context("RIPEstat недоступен")?
        .error_for_status().context("Ошибка RIPEstat")?
        .json().await.context("Некорректный ответ RIPEstat")?;
    let mut plan = parse_plan(asn, &json)?;
    if let Ok(response) = client.get(format!("{RIPESTAT}/as-overview/data.json"))
        .query(&[("resource", format!("AS{asn}"))]).send().await {
        if let Ok(response) = response.error_for_status() {
            if let Ok(json) = response.json::<Value>().await {
                plan.holder = json.pointer("/data/holder").and_then(Value::as_str)
                    .map(str::to_owned).filter(|s| !s.is_empty());
            }
        }
    }
    Ok(plan)
}

fn parse_plan(asn: u32, json: &Value) -> Result<ScanPlan> {
    let items = json.pointer("/data/prefixes").and_then(Value::as_array)
        .context("RIPEstat не вернул список IPv4-префиксов")?;
    let mut spans: Vec<(u32,u32)> = Vec::new();
    for item in items {
        let Some(value) = item.get("prefix").and_then(Value::as_str) else { continue };
        let Ok(net) = value.parse::<Ipv4Net>() else { continue };
        let net = net.trunc();
        spans.push((u32::from(net.network()), u32::from(net.broadcast())));
    }
    if spans.is_empty() {
        bail!("В ответе RIPEstat нет анонсируемых IPv4-префиксов для AS{asn}");
    }
    let observed_prefixes = spans.len();
    spans.sort_unstable();
    let mut merged: Vec<(u32,u32)> = Vec::new();
    for (start,end) in spans {
        if let Some(last) = merged.last_mut() {
            if start as u64 <= last.1 as u64 + 1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start,end));
    }
    let mut ranges = Vec::with_capacity(merged.len());
    let mut total = 0u64;
    for (start,end) in merged {
        ranges.push(Range { start, end, offset: total });
        total += end as u64 - start as u64 + 1;
    }
    Ok(ScanPlan { asn, holder: None, observed_prefixes, total, ranges })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn parses_network_identity() {
        let data = json!({"data":{"asns":[16509,14618],"prefix":"203.0.113.0/24"}});
        let (asns,prefix) = parse_network_info(&data);
        assert_eq!(asns, vec![16509,14618]);
        assert_eq!(prefix.as_deref(),Some("203.0.113.0/24"));
    }
    #[test]
    fn validates_asn() {
        assert_eq!(parse_asn("AS3333").unwrap(),3333);
        assert_eq!(parse_asn("3333").unwrap(),3333);
        assert!(parse_asn("AS0").is_err());
        assert!(parse_asn("AS33;exit").is_err());
    }
    #[test]
    fn counts_unique_ips_after_merging_nested_and_adjacent_prefixes() {
        let data=json!({"data":{"prefixes":[
            {"prefix":"192.0.2.0/25"},{"prefix":"192.0.2.0/24"},
            {"prefix":"192.0.2.128/25"},{"prefix":"198.51.100.0/30"},
            {"prefix":"198.51.100.4/30"},{"prefix":"2001:db8::/32"}
        ]}});
        let plan=parse_plan(14618,&data).unwrap();
        assert_eq!(plan.total,264);
        assert_eq!(plan.observed_prefixes,5);
        assert_eq!(plan.ranges.len(),2);
        assert_eq!(plan.selected(4_096,false),264);
        assert_eq!(plan.selected(64,false),64);
        assert!(plan.preview(64).contains("64 из 264"));
    }
    #[test]
    fn sample_spreads_across_networks_and_never_repeats() {
        let data=json!({"data":{"prefixes":[
            {"prefix":"192.0.2.0/24"},{"prefix":"198.51.100.0/24"}
        ]}});
        let plan=parse_plan(64500,&data).unwrap();
        let list: Vec<Ipv4Addr>=(0..32).map(|i|plan.address_at(i,32)).collect();
        let unique:std::collections::HashSet<_>=list.iter().collect();
        assert_eq!(unique.len(),32);
        assert_eq!(list.first().unwrap().octets()[0],192);
        assert_eq!(list.last().unwrap().octets()[0],198);
        let full:Vec<Ipv4Addr>=(0..plan.total).map(|i|plan.address_at(i,plan.total)).collect();
        assert_eq!(full.len(),512);
        assert_eq!(full[0],Ipv4Addr::new(192,0,2,0));
        assert_eq!(full[511],Ipv4Addr::new(198,51,100,255));
    }
    #[test]
    fn full_ipv4_space_has_correct_u64_count() {
        let data=json!({"data":{"prefixes":[{"prefix":"0.0.0.0/0"}]}});
        let plan=parse_plan(1,&data).unwrap();
        assert_eq!(plan.total,4_294_967_296);
        assert_eq!(plan.address_at(0,1),Ipv4Addr::new(128,0,0,0));
        assert_eq!(plan.address_at(0,plan.total),Ipv4Addr::new(0,0,0,0));
        assert_eq!(plan.address_at(plan.total-1,plan.total),Ipv4Addr::new(255,255,255,255));
    }
}
