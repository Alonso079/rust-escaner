//! Punto de entrada principal.
use anyhow::Result;
use clap::Parser;
use shodan_pipeline::{
    args::{Args, Cmd},
    config::{load_key_from_file, save_key, config_file},
    dynamic::run_dynamic_tools,
    models::IpPorts,
    nmap::{nmap_many_with_progress, split_ports, confirm_tcpwrapped},
    output::{export_csv, export_json, export_markdown, read_jsonl, summarize, write_jsonl, print_host_details, print_host_details_with_interest, filter_ports, is_interesting_host},
    rules::{load_rules, Rules},
    rustscan::rustscan_many_with_progress,
    shodan::{build_dork_from_keywords, http_client, shodan_collect, shodan_precheck_count},
    targets::{load_targets, resolve_targets},
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // Resolución de API key en orden de prioridad:
    // 1. --key
    // 2. Variable de entorno SHODAN_API_KEY
    // 3. Archivo de config (~/.config/shodan-pipeline/api_key)
    let key_resolved = if let Some(k) = &args.key { Some(k.clone()) }
        else if let Ok(k) = std::env::var("SHODAN_API_KEY") { Some(k) }
        else { load_key_from_file() };

    // Para subcomando Config permitimos que no exista key previa.

    tokio::fs::create_dir_all(&args.out).await.ok();

    let debug = args.debug;
    match args.cmd.clone() {
    Cmd::Config { set, show_path } => {
            if let Some(value) = set {
                let path = save_key(&value)?;
                println!("[+] API key guardada en {}", path.display());
            } else if show_path {
                let path = config_file()?;
                println!("Ruta archivo key: {}", path.display());
            } else if let Some(k) = key_resolved {
                println!("API key actual (oculta): {}***", &k.chars().take(3).collect::<String>());
            } else {
                println!("No hay API key configurada. Usa --key en un comando o 'shodan-pipeline config --set <KEY>'.");
            }
            return Ok(());
        }
    Cmd::Full { keywords, limit, interesting_target, interesting_min_open, pages, targets, fixed_ports, rs_concurrency, nmap_concurrency, nmap_extra, rules, resume, hide_tcpwrapped, only_open, confirm_wrapped, hunt, hunt_needed, hunt_min_open, hunt_batch } => {
            let key = key_resolved.expect("Falta API key (usa --key, variable SHODAN_API_KEY o 'config --set')");
            let client = http_client()?;
            let mut query = build_dork_from_keywords(&keywords);
            println!("[*] Dork Shodan: {query}");
            if let Err(e) = shodan_precheck_count(&client, &key, &query).await {
                eprintln!("[WARN] Dork inválido (/count): {e}");
                eprintln!("[WARN] Fallback a country:CL");
                query = "country:CL".into();
                println!("[*] Dork Fallback: {query}");
            }
            if debug { eprintln!("[DEBUG] Iniciando recolección Shodan limit={limit} pages={pages}"); }

            // 1) Shodan → IPs (modo simple o adaptativo)
            let mut ip_seed = shodan_collect(&client, &key, &query, limit, pages, &args.out, debug).await?;
            println!("[*] Shodan → {} IPs", ip_seed.len());
            if hunt {
                use std::cmp::min;
                use shodan_pipeline::models::HostReport;
                println!("[HUNT] Objetivo: {} host(s) interesantes (>= {} puertos abiertos) en lotes de {}", hunt_needed, hunt_min_open, hunt_batch);
                let mut needed = hunt_needed;
                let mut cursor = 0usize;
                let mut all_reports: Vec<HostReport> = Vec::new();
                let mut interesting: Vec<HostReport> = Vec::new();

                while needed > 0 && cursor < ip_seed.len() {
                    let end = min(cursor + hunt_batch, ip_seed.len());
                    let batch = &ip_seed[cursor..end];
                    cursor = end;
                    println!("[HUNT] Lote {}..{} ({} IPs)", end.saturating_sub(batch.len()), end, batch.len());
                    let hunt_nmap_only = std::env::var("RUST_SHODAN_HUNT_NMAP_ONLY").map(|v| v=="1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
                    if hunt_nmap_only { println!("[HUNT] Modo solo Nmap habilitado (RUST_SHODAN_HUNT_NMAP_ONLY=1)"); }
                    // RustScan lote
                    let ports_map = if let Some(fp) = &fixed_ports {
                        let fixed = split_ports(fp)?; let mut m = BTreeMap::new(); for ip in batch { m.insert(ip.clone(), fixed.clone()); } m
                    } else {
                        if hunt_nmap_only {
                            // Mapa vacío para permitir que Nmap use su set por defecto (top 1000) sin pre-descubrimiento.
                            let mut m = BTreeMap::new();
                            for ip in batch { m.insert(ip.clone(), Vec::new()); }
                            m
                        } else {
                            let rs = rustscan_many_with_progress(&batch.to_vec(), rs_concurrency, 1500, 4500).await?; let mut m = BTreeMap::new(); for r in rs { m.insert(r.ip, r.ports); } m
                        }
                    };
                    // Nmap lote
                    let pairs: Vec<(String,String)> = batch.iter().map(|ip| (ip.clone(), ip.clone())).collect();
                    let mut reports = nmap_many_with_progress(&pairs, &ports_map, &args.out, &nmap_extra, fixed_ports.as_deref(), nmap_concurrency, resume).await?;
                    if confirm_wrapped { println!("[*] Confirmando puertos tcpwrapped..."); confirm_tcpwrapped(&mut reports).await.ok(); }
                    // Filtro y conteo
                    for mut rep in reports { rep.ports = filter_ports(&rep.ports, hide_tcpwrapped, only_open); if is_interesting_host(&rep.ports, hunt_min_open) { if !interesting.iter().any(|x| x.ip == rep.ip) { interesting.push(rep.clone()); if needed>0 { needed -=1; println!("[HUNT] +1 interesante {} (faltan {})", rep.ip, needed); } } } all_reports.push(rep); }
                    if needed == 0 { println!("[HUNT] Cupo alcanzado. Deteniendo."); break; }
                    if cursor >= ip_seed.len() && ip_seed.len() < limit { println!("[HUNT] IPs agotadas y aún faltan interesantes."); break; }
                }
                summarize(&all_reports);
                print_host_details_with_interest(&all_reports, hide_tcpwrapped, only_open, hunt_min_open);
                export_csv(&args.out.join("report.csv"), &all_reports, hide_tcpwrapped, only_open)?;
                export_json(&args.out.join("report.json"), &all_reports, hide_tcpwrapped, only_open)?;
                export_markdown(&args.out.join("report.md"), &all_reports, hide_tcpwrapped, only_open)?;
                export_csv(&args.out.join("report_interesting.csv"), &interesting, hide_tcpwrapped, only_open)?;
                export_json(&args.out.join("report_interesting.json"), &interesting, hide_tcpwrapped, only_open)?;
                println!("CSV → {}", args.out.join("report.csv").display());
                println!("JSON → {}", args.out.join("report.json").display());
                println!("MD  → {}", args.out.join("report.md").display());
                println!("CSV (interesantes) → {}", args.out.join("report_interesting.csv").display());
                println!("JSON (interesantes) → {}", args.out.join("report_interesting.json").display());
                return Ok(());
            }
            let mut interesting_found = 0usize;
            let adaptive = interesting_target > 0;

            // 2) targets externos (IPs o dominios)
            if let Some(tfile) = targets {
                let raw_targets = load_targets(&tfile).await?;
                let resolved = resolve_targets(&raw_targets).await?;
                for (_t, ip) in resolved { if !ip_seed.contains(&ip) { ip_seed.push(ip); } }
                let list_path = args.out.join("ips.txt");
                fs::write(&list_path, ip_seed.join("\n"))?;
                println!("[*] Targets combinados → {}", ip_seed.len());
            }

            // Dedup ordenado
            let mut ip_seed: Vec<String> = {
                let mut s = BTreeSet::new();
                for ip in ip_seed { s.insert(ip); }
                s.into_iter().collect()
            };

            // Permite forzar modo adaptativo solo-Nmap (sin RustScan) vía variable de entorno.
            let adaptive_nmap_only = std::env::var("RUST_SHODAN_ADAPTIVE_NMAP_ONLY").map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);
            if adaptive_nmap_only { println!("[ADAPT] Modo solo Nmap habilitado (RUST_SHODAN_ADAPTIVE_NMAP_ONLY=1)"); }

            // Instrumentación: función interna para escanear actual conjunto y actualizar interés
            let mut aggregated_reports: Vec<shodan_pipeline::models::HostReport> = Vec::new();
            let mut already_scanned: BTreeSet<String> = BTreeSet::new();
            loop {
                // Filtrar IPs nuevas no escaneadas
                let remaining: Vec<String> = ip_seed.iter().filter(|ip| !already_scanned.contains(*ip)).cloned().collect();
                if remaining.is_empty() { break; }
                // 3) RustScan/Nmap para remaining
                let ports_map: BTreeMap<String, Vec<u16>> = if let Some(fp) = &fixed_ports {
                        if debug { eprintln!("[DEBUG] Modo matriz: Nmap puertos fijos = {fp}"); }
                        let fixed = split_ports(fp)?;
                        let mut m = BTreeMap::new();
                        for ip in &remaining { m.insert(ip.clone(), fixed.clone()); }
                        m
                    } else if adaptive_nmap_only {
                        // Mapa vacío: nmap_one_host detectará lista vacía y dejará que Nmap use top 1000.
                        if debug { eprintln!("[DEBUG] Adaptive Nmap-only: usando set por defecto de Nmap (sin RustScan)"); }
                        let mut m = BTreeMap::new();
                        for ip in &remaining { m.insert(ip.clone(), Vec::new()); }
                        m
                    } else {
                        let rs = rustscan_many_with_progress(&remaining, rs_concurrency, 1500, 4500).await?;
                        let jsonl_path = args.out.join("rustscan.jsonl");
                        // Append JSONL incremental
                        let mut file = if jsonl_path.exists() { std::fs::OpenOptions::new().append(true).open(&jsonl_path)? } else { std::fs::File::create(&jsonl_path)? };
                        for r in &rs { use std::io::Write; writeln!(file, "{}", serde_json::to_string(r)?)?; }
                        let mut m = BTreeMap::new();
                        for r in rs { m.insert(r.ip, r.ports); }
                        m
                    };
                let target_pairs: Vec<(String, String)> = remaining.iter().map(|ip| (ip.clone(), ip.clone())).collect();
                let mut batch_reports = nmap_many_with_progress(&target_pairs, &ports_map, &args.out, &nmap_extra, fixed_ports.as_deref(), nmap_concurrency, resume).await?;
                if confirm_wrapped { println!("[*] Confirmando puertos tcpwrapped..."); confirm_tcpwrapped(&mut batch_reports).await.ok(); }
                // Actualizar contadores
                for r in &batch_reports {
                    let open_count = r.ports.iter().filter(|p| p.state == "open").count();
                    if open_count >= interesting_min_open { interesting_found += 1; }
                    already_scanned.insert(r.ip.clone());
                }
                aggregated_reports.extend(batch_reports);
                if adaptive {
                    println!("[ADAPT] Interesantes: {interesting_found}/{interesting_target} (umbral {interesting_min_open} puertos abiertos)");
                    if interesting_found >= interesting_target { println!("[ADAPT] Objetivo alcanzado – deteniendo."); break; }
                    // Si no alcanzado y ya consumimos todas las IPs recolectadas, intentar pedir más páginas extra si posible
                    if already_scanned.len() == ip_seed.len() {
                        if ip_seed.len() >= limit { println!("[ADAPT] Límite rígido de IPs alcanzado ({limit}), deteniendo."); break; }
                        // Pedimos una página adicional si pages permitía más
                        let extra_page_window = 5usize; // pequeñas expansiones
                        let new_limit = (ip_seed.len() + 5).min(limit);
                        let add = shodan_collect(&client, &key, &query, new_limit, pages + extra_page_window, &args.out, debug).await?;
                        let before = ip_seed.len();
                        for ip in add { if !ip_seed.contains(&ip) { ip_seed.push(ip); } }
                        if ip_seed.len() == before { println!("[ADAPT] No se obtuvieron IPs nuevas adicionales."); break; }
                        println!("[ADAPT] Ampliado conjunto a {} IPs", ip_seed.len());
                        continue; // volver al loop para escanear nuevas
                    }
                } else { break; }
            }
            let reports = aggregated_reports;

            // 5) Reglas dinámicas
            let rules_cfg = load_rules(&rules).unwrap_or_else(|_| Rules { rules: vec![] });
            if rules_cfg.rules.is_empty() { println!("[*] rules.yaml vacío o no encontrado; saltando herramientas dinámicas."); }
            else { run_dynamic_tools(&rules_cfg, &reports, &args.out).await?; }

            // 6) Resumen + CSV + detalle
            summarize(&reports);
            let interest_threshold = if adaptive { interesting_min_open } else { 0 };
            if interest_threshold > 0 { print_host_details_with_interest(&reports, hide_tcpwrapped, only_open, interest_threshold); } else { print_host_details(&reports, hide_tcpwrapped, only_open); }
            export_csv(&args.out.join("report.csv"), &reports, hide_tcpwrapped, only_open)?;
            export_json(&args.out.join("report.json"), &reports, hide_tcpwrapped, only_open)?;
            println!("CSV → {}", args.out.join("report.csv").display());
            println!("JSON → {}", args.out.join("report.json").display());
        }
        Cmd::Intel { keywords, limit, pages } => {
            let key = key_resolved.expect("Falta API key (usa --key, variable SHODAN_API_KEY o 'config --set')");
            let client = http_client()?;
            let mut query = build_dork_from_keywords(&keywords);
            println!("[*] Dork Shodan: {query}");
            if let Err(e) = shodan_precheck_count(&client, &key, &query).await {
                eprintln!("[WARN] Dork inválido (/count): {e}");
                eprintln!("[WARN] Fallback a country:CL");
                query = "country:CL".into();
                println!("[*] Dork Fallback: {query}");
            }
            let _ips = shodan_collect(&client, &key, &query, limit, pages, &args.out, debug).await?;
        }
        Cmd::Clean { deep } => {
            if args.out.exists() { std::fs::remove_dir_all(&args.out).ok(); }
            println!("[+] Borrado directorio out/" );
            if deep { std::fs::remove_dir_all("target").ok(); println!("[+] Borrado target/ (recompilación completa la próxima vez)"); }
        }
        Cmd::Rustscan { input_targets, timeout_ms, batch, concurrency } => {
            let raw = load_targets(&input_targets).await?;
            let pairs = resolve_targets(&raw).await?;
            let ips: Vec<String> = pairs.into_iter().map(|(_, ip)| ip).collect();
            let rs = rustscan_many_with_progress(&ips, concurrency, timeout_ms, batch).await?;
            let jsonl_path = input_targets.with_extension("rustscan.jsonl");
            write_jsonl(&jsonl_path, &rs)?;
            println!("RustScan JSONL → {}", jsonl_path.display());
        }
    Cmd::Nmap { input_jsonl, fixed_ports, nmap_extra, concurrency, resume, hide_tcpwrapped, only_open, confirm_wrapped } => {
            use anyhow::anyhow;
            let (targets, ports_map): (Vec<(String, String)>, BTreeMap<String, Vec<u16>>) = if let Some(fp) = fixed_ports.clone() {
                let tuple = if let Some(path) = input_jsonl.clone() {
                    let items: Vec<IpPorts> = read_jsonl(&path).await?;
                    let ips: Vec<String> = items.into_iter().map(|x| x.ip).collect();
                    (ips, split_ports(&fp)?)
                } else { return Err(anyhow!("Con --fixed-ports necesitas también --input-jsonl o adaptar código para leer out/ips.txt")); };
                let pairs: Vec<(String, String)> = tuple.0.iter().map(|ip| (ip.clone(), ip.clone())).collect();
                let mut map = BTreeMap::new();
                for ip in tuple.0 { map.insert(ip, tuple.1.clone()); }
                (pairs, map)
            } else {
                let path = input_jsonl.clone().expect("Falta --input-jsonl o usa --fixed-ports");
                let items: Vec<IpPorts> = read_jsonl(&path).await?;
                let pairs: Vec<(String, String)> = items.iter().map(|it| (it.ip.clone(), it.ip.clone())).collect();
                let mut map = BTreeMap::new();
                for it in items { map.insert(it.ip, it.ports); }
                (pairs, map)
            };
            let mut reports = nmap_many_with_progress(&targets, &ports_map, &args.out, &nmap_extra, fixed_ports.as_deref(), concurrency, resume).await?;
            if confirm_wrapped { println!("[*] Confirmando puertos tcpwrapped..."); confirm_tcpwrapped(&mut reports).await.ok(); }
            summarize(&reports);
            print_host_details(&reports, hide_tcpwrapped, only_open);
            export_csv(&args.out.join("report.csv"), &reports, hide_tcpwrapped, only_open)?;
            export_json(&args.out.join("report.json"), &reports, hide_tcpwrapped, only_open)?;
            println!("CSV → {}", args.out.join("report.csv").display());
            println!("JSON → {}", args.out.join("report.json").display());
        }
    }
    Ok(())
}
