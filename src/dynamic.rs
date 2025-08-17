use anyhow::Result;
use regex::Regex;
use tokio::process::Command;
use crate::{rules::Rules, models::HostReport};

pub async fn run_dynamic_tools(rules: &Rules, reports: &Vec<HostReport>, out: &std::path::Path) -> Result<()> {
    for h in reports { if h.ports.is_empty(){ continue; } let ip_dir = out.join(&h.ip); tokio::fs::create_dir_all(&ip_dir).await.ok(); for p in &h.ports { let mut matched_cmds: Vec<(&str, &String)> = Vec::new(); for rule in &rules.rules { let port_match = !rule.ports.is_empty() && rule.ports.contains(&p.port); let mut service_match = false; if let Some(re)= &rule.service_regex { if let Some(svc)= &p.service { if Regex::new(re).ok().map(|r| r.is_match(svc)).unwrap_or(false){ service_match = true; } } } if port_match || (rule.service_regex.is_some() && service_match) { for cmd in &rule.cmds { matched_cmds.push((&rule.name, cmd)); } } } for (rname, cmd_tpl) in matched_cmds { let cmd_line = cmd_tpl.replace("{ip}", &h.ip).replace("{target}", &h.target).replace("{port}", &p.port.to_string()).replace("{service}", &p.service.clone().unwrap_or_default()); println!("[{}] {}: {}", h.ip, rname, cmd_line); let log_path = ip_dir.join(format!("{}_{}.log", rname, p.port)); run_and_log(&cmd_line, &log_path).await?; } } }
    Ok(())
}

async fn run_and_log(cmd_line: &str, log_path: &std::path::Path) -> Result<()> { let parts = shell_words::split(cmd_line)?; if parts.is_empty(){ return Ok(()); } let (bin, args) = parts.split_first().unwrap(); let output = Command::new(bin).args(args).output().await?; let mut content = String::new(); content.push_str(&format!("$ {}\n\n", cmd_line)); content.push_str(&String::from_utf8_lossy(&output.stdout)); if !output.stderr.is_empty(){ content.push_str("\n[stderr]\n"); content.push_str(&String::from_utf8_lossy(&output.stderr)); } tokio::fs::write(log_path, content).await?; Ok(()) }
