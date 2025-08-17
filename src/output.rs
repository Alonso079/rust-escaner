use anyhow::Result;
use crate::models::{HostReport, IpPorts, PortDetail};
use std::fs;

pub fn summarize(reports: &[HostReport]) {
	let total_hosts = reports.len();
	let mut open_total = 0usize;
	let mut closed_total = 0usize;
	let mut filtered_total = 0usize;
	for r in reports { for p in &r.ports { match p.state.as_str() { "open" => open_total += 1, "closed" => closed_total += 1, "filtered" => filtered_total += 1, _ => {} } } }
	println!("=== RESUMEN ===");
	println!("Hosts: {}", total_hosts);
	println!("Puertos abiertos:   {}", open_total);
	println!("Puertos cerrados:   {}", closed_total);
	println!("Puertos filtrados:  {}", filtered_total);
}

pub fn filter_ports(ports: &[PortDetail], hide_tcpwrapped: bool, only_open: bool) -> Vec<PortDetail> {
	let mut v: Vec<PortDetail> = ports.iter().filter(|p| {
		(!only_open || p.state == "open") && (!hide_tcpwrapped || p.service.as_deref() != Some("tcpwrapped"))
	}).cloned().collect();
	v.sort_by_key(|p| p.port);
	v
}

pub fn print_host_details(reports: &[HostReport], hide_tcpwrapped: bool, only_open: bool) {
	println!("=== DETALLE PUERTOS POR HOST ===");
	for h in reports {
		let filtered = filter_ports(&h.ports, hide_tcpwrapped, only_open);
		println!("{} ({})", h.ip, h.target);
		if filtered.is_empty() { println!("  (sin puertos tras filtro)"); continue; }
		let mut conocidos = Vec::new();
		let mut otros = Vec::new();
		for p in filtered { match p.service.as_deref() { Some("tcpwrapped") | None | Some("unknown") => otros.push(p), _ => conocidos.push(p) } }
		if !conocidos.is_empty() {
			let list = conocidos.iter().map(|p| format!("{}:{}:{}", p.port, p.service.as_deref().unwrap_or(""), p.state)).collect::<Vec<_>>().join(", ");
			println!("  conocidos: {}", list);
		}
		if !otros.is_empty() {
			let show = 15usize.min(otros.len());
			let list = otros.iter().take(show).map(|p| format!("{}:{}:{}", p.port, p.service.as_deref().unwrap_or(""), p.state)).collect::<Vec<_>>().join(", ");
			println!("  otros({}): {}", otros.len(), list);
			if otros.len() > show { println!("  ... +{} más", otros.len() - show); }
		}
	}
}

/// Versión extendida que marca con ★ los hosts considerados "interesantes" (>= min_open tras filtros).
pub fn print_host_details_with_interest(reports: &[HostReport], hide_tcpwrapped: bool, only_open: bool, min_open: usize) {
	println!("=== DETALLE PUERTOS POR HOST ===");
	for h in reports {
		let filtered = filter_ports(&h.ports, hide_tcpwrapped, only_open);
		let open_count = filtered.iter().filter(|p| p.state == "open").count();
		let star = if min_open > 0 && open_count >= min_open { "★ " } else { "" };
		println!("{}{} ({})", star, h.ip, h.target);
		if filtered.is_empty() { println!("  (sin puertos tras filtro)"); continue; }
		let mut conocidos = Vec::new();
		let mut otros = Vec::new();
		for p in filtered { match p.service.as_deref() { Some("tcpwrapped") | None | Some("unknown") => otros.push(p), _ => conocidos.push(p) } }
		if !conocidos.is_empty() {
			let list = conocidos.iter().map(|p| format!("{}:{}:{}", p.port, p.service.as_deref().unwrap_or(""), p.state)).collect::<Vec<_>>().join(", ");
			println!("  conocidos: {}", list);
		}
		if !otros.is_empty() {
			let show = 15usize.min(otros.len());
			let list = otros.iter().take(show).map(|p| format!("{}:{}:{}", p.port, p.service.as_deref().unwrap_or(""), p.state)).collect::<Vec<_>>().join(", ");
			println!("  otros({}): {}", otros.len(), list);
			if otros.len() > show { println!("  ... +{} más", otros.len() - show); }
		}
	}
}

pub fn export_csv(path: &std::path::Path, reports: &[HostReport], hide_tcpwrapped: bool, only_open: bool) -> Result<()> {
	let mut wtr = csv::Writer::from_path(path)?;
	wtr.write_record(&["target","ip","port","state","service"])?;
	for r in reports {
		let ports = filter_ports(&r.ports, hide_tcpwrapped, only_open);
		for p in ports { wtr.write_record(&[ &r.target, &r.ip, &p.port.to_string(), &p.state, p.service.as_deref().unwrap_or("") ])?; }
	}
	wtr.flush()?;
	Ok(())
}

pub fn export_json(path: &std::path::Path, reports: &[HostReport], hide_tcpwrapped: bool, only_open: bool) -> Result<()> {
	#[derive(serde::Serialize)]
	struct JPort { port: u16, state: String, service: Option<String> }
	#[derive(serde::Serialize)]
	struct JHost<'a> { target: &'a str, ip: &'a str, ports: Vec<JPort> }
	let mut out = Vec::new();
	for r in reports {
		let ports = filter_ports(&r.ports, hide_tcpwrapped, only_open).into_iter()
			.map(|p| JPort { port: p.port, state: p.state, service: p.service })
			.collect();
		out.push(JHost { target: &r.target, ip: &r.ip, ports });
	}
	fs::write(path, serde_json::to_string_pretty(&out)?)?;
	Ok(())
}

pub fn export_markdown(path: &std::path::Path, reports: &[HostReport], hide_tcpwrapped: bool, only_open: bool) -> Result<()> {
	let mut md = String::new();
	md.push_str("# Reporte de Escaneo\n\n");
	for r in reports {
		md.push_str(&format!("## {} ({})\n\n", r.ip, r.target));
		let filtered = filter_ports(&r.ports, hide_tcpwrapped, only_open);
		if filtered.is_empty() { md.push_str("_Sin puertos tras filtro._\n\n"); continue; }
		md.push_str("| Puerto | Estado | Servicio |\n|-------:|--------|----------|\n");
		for p in filtered { md.push_str(&format!("| {} | {} | {} |\n", p.port, p.state, p.service.unwrap_or_default())); }
		md.push('\n');
	}
	fs::write(path, md)?; Ok(())
}

pub fn count_open_after_filter(ports: &[PortDetail]) -> usize { ports.iter().filter(|p| p.state == "open").count() }
pub fn is_interesting_host(ports: &[PortDetail], min_open: usize) -> bool { count_open_after_filter(ports) >= min_open }

pub fn write_jsonl(path: &std::path::Path, items: &Vec<IpPorts>) -> Result<()> {
	let mut out = String::new();
	for it in items { out.push_str(&serde_json::to_string(it)?); out.push('\n'); }
	fs::write(path, out)?; Ok(())
}

pub async fn read_jsonl(path: &std::path::Path) -> Result<Vec<IpPorts>> {
	let text = tokio::fs::read_to_string(path).await?;
	let mut v = Vec::new();
	for line in text.lines() { if line.trim().is_empty(){ continue; } let item: IpPorts = serde_json::from_str(line)?; v.push(item); }
	Ok(v)
}
