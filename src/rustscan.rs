use anyhow::{Result, Context};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::{process::Command, io::{AsyncBufReadExt, BufReader}, sync::Semaphore};
use std::sync::Arc;
use crate::models::IpPorts;

async fn rustscan_one(ip: &str, timeout_ms: u64, batch: u32) -> Result<Vec<u16>> {
    let mut cmd = Command::new("rustscan"); cmd.arg("-a").arg(ip).arg("--timeout").arg(timeout_ms.to_string()).arg("--batch-size").arg(batch.to_string()).arg("--greppable").stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().with_context(|| format!("No pude lanzar rustscan para {ip}"))?; let stdout = child.stdout.take().unwrap(); let mut reader = BufReader::new(stdout).lines();
    let mut ports = Vec::<u16>::new(); while let Some(line) = reader.next_line().await? { if let Some((_ip, list)) = line.split_once("->") { for p in list.split(',') { if let Ok(n)= p.trim().parse::<u16>() { ports.push(n); } } } }
    let _ = child.wait().await?; ports.sort_unstable(); ports.dedup(); Ok(ports)
}

pub async fn rustscan_many_with_progress(ips: &Vec<String>, concurrency: usize, timeout_ms: u64, batch: u32) -> Result<Vec<IpPorts>> {
    let total = ips.len() as u64; let pb = ProgressBar::new(total); pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.green/black} {pos}/{len} ({percent}%) RustScan")?.progress_chars("##-"));
    let sem = Arc::new(Semaphore::new(concurrency)); let mut tasks = Vec::new(); for ip in ips { let ip = ip.clone(); let s = sem.clone(); let pb2 = pb.clone(); tasks.push(tokio::spawn(async move { let _permit = s.acquire_owned().await.unwrap(); let ports = rustscan_one(&ip, timeout_ms, batch).await.unwrap_or_default(); pb2.inc(1); IpPorts { ip, ports } })); }
    let mut results = Vec::new(); for t in tasks { results.push(t.await?); } pb.finish_with_message("RustScan listo"); Ok(results)
}
