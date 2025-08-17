use anyhow::Result;
use trust_dns_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};

pub async fn load_targets(path: &std::path::Path) -> Result<Vec<String>> { let s = tokio::fs::read_to_string(path).await?; Ok(s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()) }

pub async fn resolve_targets(targets: &[String]) -> Result<Vec<(String, String)>> { let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()); let mut out = Vec::new(); for t in targets { if t.parse::<std::net::IpAddr>().is_ok(){ out.push((t.clone(), t.clone())); continue; } if let Ok(lookup) = resolver.lookup_ip(t.as_str()).await { if let Some(ip)= lookup.iter().next(){ out.push((t.clone(), ip.to_string())); } } } Ok(out) }
