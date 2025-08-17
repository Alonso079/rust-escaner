use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use std::{collections::BTreeMap, path::Path};
use tokio::process::Command;
use tokio::sync::Semaphore;
use std::sync::Arc;
use crate::models::{HostReport, PortDetail};

/// Detecta si el proceso corre con privilegios (uid efectivo 0) en Linux leyendo /proc/self/status.
fn is_root() -> bool {
    #[cfg(unix)]
    unsafe { libc::geteuid() == 0 }
    #[cfg(not(unix))]
    { false }
}

/// Normaliza flags extra de Nmap para evitar combinaciones inválidas:
/// - Si hay -sS y no eres root -> cambia a -sT (avisa)
/// - Si el modo final es -sT -> elimina flags específicos de SYN como --defeat-rst-ratelimit
/// - Evita coexistencia -sS y -sT (prioriza -sT si presente)
/// - Si no hay ninguno, añade -sT por seguridad
fn normalize_nmap_extra(extra: &str, ip_hint: Option<&str>) -> Vec<String> {
    let mut v: Vec<String> = extra.split_whitespace().map(|s| s.to_string()).collect();
    let have_root = is_root();

    if v.iter().any(|a| a == "-sS") && !have_root {
        eprintln!("[INFO] Sin privilegios para SYN (-sS); usando -sT{}", ip_hint.map(|i| format!(" en {i}")).unwrap_or_default());
        for a in &mut v { if a == "-sS" { *a = "-sT".into(); } }
    }
    // Si tendremos -sT (explícito o por sustitución) remover flags solo válidos con -sS
    if v.iter().any(|a| a == "-sT") {
        let before = v.len();
        v.retain(|a| a != "--defeat-rst-ratelimit");
        if v.len() != before { eprintln!("[INFO] Removido --defeat-rst-ratelimit (solo válido con -sS{})", ip_hint.map(|i| format!(" para {i}")).unwrap_or_default()); }
    }
    // Eliminar -sS si queda junto a -sT
    if v.iter().any(|a| a == "-sT") { v.retain(|a| a != "-sS"); }
    // Asegurar que exista un modo de escaneo
    if !v.iter().any(|a| a == "-sT" || a == "-sS") { v.insert(0, if have_root { "-sS".into() } else { "-sT".into() }); }
    v
}

pub fn split_ports(s: &str) -> Result<Vec<u16>> { let mut out = Vec::new(); for part in s.split(',') { let p = part.trim(); if p.is_empty(){ continue; } if let Some((a,b)) = p.split_once('-') { let a: u16 = a.trim().parse()?; let b: u16 = b.trim().parse()?; if a <= b { for x in a..=b { out.push(x); } } } else { out.push(p.parse()?); } } out.sort_unstable(); out.dedup(); Ok(out) }

pub async fn nmap_many_with_progress(targets: &[(String, String)], ports_map: &BTreeMap<String, Vec<u16>>, out_dir: &Path, extra: &str, fixed_ports: Option<&str>, concurrency: usize, resume: bool) -> Result<Vec<HostReport>> {
    let total = targets.len() as u64; let pb = ProgressBar::new(total); pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.blue/black} {pos}/{len} ({percent}%) Nmap")?.progress_chars("##-"));
    let sem = Arc::new(Semaphore::new(concurrency)); let mut tasks = Vec::new(); for (target, ip) in targets { let target = target.clone(); let ip = ip.clone(); let s = sem.clone(); let pb2 = pb.clone(); let out = out_dir.to_path_buf(); let extra = extra.to_string(); let fixed = fixed_ports.map(|x| x.to_string()); let ports = ports_map.get(&ip).cloned().unwrap_or_default(); tasks.push(tokio::spawn(async move { let _permit = s.acquire_owned().await.unwrap(); let rep = nmap_one_host(&target, &ip, &ports, &out, &extra, fixed.as_deref(), resume).await; pb2.inc(1); rep })); }
    let mut reports = Vec::new(); for t in tasks { reports.push(t.await??); } pb.finish_with_message("Nmap listo"); Ok(reports)
}

/// Re-confirma puertos marcados como tcpwrapped intentando un escaneo rápido -sT -Pn sobre ellos.
/// Si -sT falla intenta -sS (caso inverso al fallback principal) para completar mejor cobertura.
pub async fn confirm_tcpwrapped(reports: &mut [HostReport]) -> Result<()> {
    for r in reports.iter_mut() {
        let wrapped: Vec<u16> = r.ports.iter().filter(|p| p.service.as_deref() == Some("tcpwrapped")).map(|p| p.port).collect();
        if wrapped.is_empty() { continue; }
        let ip = &r.ip;
        let port_list = wrapped.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        // Primario -sT
        let primary = vec!["-sT","-Pn","-p", &port_list, ip, "-oX", "-" ];
        let output = Command::new("nmap").args(&primary).output().await?;
        let xml_bytes = if output.status.success() { output.stdout } else {
            // Fallback a -sS si falla (quizá tenemos privilegios y -sT no disponible por alguna razón rara)
            let secondary = vec!["-sS","-Pn","-p", &port_list, ip, "-oX", "-" ];
            let out2 = Command::new("nmap").args(&secondary).output().await?;
            if !out2.status.success() { continue; } else { out2.stdout }
        };
        let xml = String::from_utf8_lossy(&xml_bytes);
        if let Ok(parsed) = parse_nmap_ports(&xml) {
            for upd in parsed { if wrapped.contains(&upd.port) { if let Some(orig) = r.ports.iter_mut().find(|p| p.port == upd.port) { orig.state = upd.state; orig.service = upd.service; } } }
        }
    }
    Ok(())
}

async fn nmap_one_host(target: &str, ip: &str, ports: &[u16], out_dir: &Path, extra: &str, fixed_ports: Option<&str>, resume: bool) -> Result<HostReport> {
    let ip_dir = out_dir.join(ip); tokio::fs::create_dir_all(&ip_dir).await.ok(); let xml_path = ip_dir.join("nmap.xml");
    if resume && xml_path.exists(){ let xml = tokio::fs::read_to_string(&xml_path).await?; let ports = parse_nmap_ports(&xml)?; return Ok(HostReport{ target: target.into(), ip: ip.into(), ports }); }
    // Normalizar flags extra
    let mut args = normalize_nmap_extra(extra, Some(ip));
    if let Some(fp)= fixed_ports {
        args.extend(vec!["-p".into(), fp.to_string()]);
    } else if !ports.is_empty() {
        // Si se entrega lista de puertos descubrimiento previo (RustScan u otro), la usamos.
        let port_list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        args.extend(vec!["-p".into(), port_list]);
    } else {
        // Caso lista vacía: dejamos que Nmap utilice su set por defecto (top 1000). No añadimos -p.
        // Esto habilita un modo "solo Nmap" cuando se omite RustScan en el bucle adaptativo.
    }
    args.extend(vec![ip.to_string(), "-oX".into(), xml_path.to_string_lossy().into_owned()]);
    // Ejecutamos capturando stdout/err para decidir fallback
    let output = Command::new("nmap").args(&args).output().await?;
    let mut succeeded = output.status.success();
    if !succeeded && args.iter().any(|a| a == "-sS") && !args.iter().any(|a| a == "-sT") {
        // Intentar fallback reemplazando -sS por -sT
        let mut args2 = args.clone();
        for a in args2.iter_mut() { if a == "-sS" { *a = "-sT".into(); } }
        eprintln!("[WARN] nmap -sS falló en {ip}, intentando fallback -sT");
        let output2 = Command::new("nmap").args(&args2).output().await?;
        if output2.status.success() {
            // Re-escribimos xml si produjo
            succeeded = true;
        } else {
            // Mantener el fallo original
        }
    }
    if !succeeded {
        // Capturar stderr (truncado) para facilitar diagnóstico y escribir a archivo
        let stderr_txt_full = String::from_utf8_lossy(&output.stderr);
        let stderr_trunc = if stderr_txt_full.len() > 600 { format!("{}...<truncado>", &stderr_txt_full[..600]) } else { stderr_txt_full.to_string() };
        let _ = tokio::fs::write(ip_dir.join("nmap.stderr.txt"), stderr_txt_full.as_bytes()).await;
        anyhow::bail!("nmap falló en {} con args {:?}. stderr: {}", ip, args, stderr_trunc);
    }
    let xml = tokio::fs::read_to_string(&xml_path).await?; let ports = parse_nmap_ports(&xml)?; Ok(HostReport { target: target.into(), ip: ip.into(), ports })
}

fn parse_nmap_ports(xml: &str) -> Result<Vec<PortDetail>> { use quick_xml::{Reader, events::Event}; let mut rd = Reader::from_str(xml); rd.config_mut().trim_text(true); let mut buf = Vec::new(); let mut current_port: Option<u16> = None; let mut current_state: Option<String> = None; let mut current_service: Option<String> = None; let mut out = Vec::<PortDetail>::new(); loop { match rd.read_event_into(&mut buf) { Ok(Event::Start(e)) if e.name().as_ref()== b"port" => { current_port=None; current_state=None; current_service=None; for a in e.attributes().flatten(){ if a.key.as_ref()== b"portid" { current_port = String::from_utf8_lossy(&a.value).parse::<u16>().ok(); } } } Ok(Event::Empty(e)) if e.name().as_ref()== b"state" => { for a in e.attributes().flatten(){ if a.key.as_ref()== b"state" { current_state = Some(String::from_utf8_lossy(&a.value).to_string()); } } } Ok(Event::Start(e)) if e.name().as_ref()== b"state" => { for a in e.attributes().flatten(){ if a.key.as_ref()== b"state" { current_state = Some(String::from_utf8_lossy(&a.value).to_string()); } } } Ok(Event::Empty(e)) if e.name().as_ref()== b"service" => { for a in e.attributes().flatten(){ if a.key.as_ref()== b"name" { current_service = Some(String::from_utf8_lossy(&a.value).to_string()); } } } Ok(Event::Start(e)) if e.name().as_ref()== b"service" => { for a in e.attributes().flatten(){ if a.key.as_ref()== b"name" { current_service = Some(String::from_utf8_lossy(&a.value).to_string()); } } } Ok(Event::End(e)) if e.name().as_ref()== b"port" => { if let Some(p)= current_port { out.push(PortDetail { port: p, state: current_state.clone().unwrap_or_else(|| "unknown".into()), service: current_service.clone() }); } current_port=None; current_state=None; current_service=None; } Ok(Event::Eof) => break, Err(e) => return Err(anyhow!("XML error: {}", e)), _ => {} } } Ok(out) }
