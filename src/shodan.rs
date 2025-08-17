use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path, fs, time::Duration};
use tokio::time::sleep;

pub fn http_client() -> Result<Client> { Ok(Client::builder().timeout(Duration::from_secs(30)).build()?) }

pub fn build_dork_from_keywords(keywords_csv: &str) -> String {
    // normaliza/dedup
    let mut kws: Vec<String> = keywords_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.replace('"', "").replace('\'', ""))
        .map(|s| s.to_lowercase())
        .collect();
    kws.dedup();

    let mut terms: Vec<String> = Vec::new();

    for kw in kws {
        match kw.as_str() {
            // país
            "chile" | "cl" => { terms.push("country:CL".into()); }
            // TLD puro tipo .cl (no contiene otro punto después)
            t if t.starts_with('.') && !t[1..].contains('.') => {
                let tld = t; // conserva el . inicial
                // Búsqueda de substring segura en varias vistas (sin disparar error 500)
                terms.push(format!("(ssl:\"{tld}\" OR http.title:\"{tld}\" OR http.html:\"{tld}\")"));
            }
            // Dominio/FQDN (contiene punto interno o empieza con punto pero con más niveles)
            t if t.starts_with('.') || t.contains('.') => {
                let v = t.trim_start_matches('.');
                if !v.is_empty() {
                    terms.push(format!("(hostname:\"{v}\" OR ssl.cert.subject.cn:\"{v}\" OR ssl.cert.issuer.cn:\"{v}\")"));
                }
            }

            // términos municipales
            "muni" | "municipalidad" | "municipio" | "ilustre" => terms.push(
                "(http.title:\"Municipalidad\" OR http.html:\"Municipalidad\" OR org:\"Municipalidad\")".into(),
            ),

            // ISO 2 letras
            t if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) => {
                terms.push(format!("country:{}", t.to_uppercase()));
            }

            // término libre
            other => terms.push(format!(
                "(http.title:\"{o}\" OR http.html:\"{o}\" OR org:\"{o}\" OR product:\"{o}\")",
                o = other
            )),
        }
    }

    if terms.is_empty() {
        return "country:CL".into();
    }
    // Dedup de cláusulas equivalentes para evitar (country:CL) AND (country:CL)
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    let mut ordered = Vec::new();
    for t in terms { if set.insert(t.clone()) { ordered.push(t); } }
    ordered.into_iter().map(|t| format!("({t})")).collect::<Vec<_>>().join(" AND ")
}

pub async fn shodan_precheck_count(client: &Client, key: &str, query: &str) -> Result<()> {
    let url = format!(
        "https://api.shodan.io/shodan/host/count?key={}&query={}",
        urlencoding::encode(key),
        urlencoding::encode(query)
    );
    let resp = client.get(&url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Precheck /count fallo ({}): {}", status, text));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::build_dork_from_keywords;

    #[test]
    fn tld_only() {
        let q = build_dork_from_keywords(".cl");
    assert!(q.contains("ssl:\".cl\""));
    assert!(q.contains("http.title:\".cl\""));
    assert!(!q.contains("hostname:\"cl\""));
    }

    #[test]
    fn chile_and_tld_and_muni() {
        let q = build_dork_from_keywords("chile,.cl,muni");
        assert!(q.contains("country:CL"));
    assert!(q.contains("ssl:\".cl\""));
        assert!(q.contains("Municipalidad"));
        assert!(q.matches(" AND ").count() >= 2);
    }

    #[test]
    fn chile_and_cl_dedup() {
        let q = build_dork_from_keywords("chile,cl");
        // Debe haber solo una aparición de country:CL
        assert!(q.matches("country:CL").count() == 1, "Dork duplicado: {q}");
    }
}

pub async fn shodan_collect(client: &Client, key: &str, query: &str, limit: usize, pages: usize, out: &Path, debug: bool) -> Result<Vec<String>> {
    let mut ips: BTreeSet<String> = BTreeSet::new();
    let max_pages = pages.max(1).min(100);
    let pb = ProgressBar::new(max_pages as u64);
    pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} pág {pos}/{len} Shodan")?.progress_chars("##-"));
    for page in 1..=max_pages { if ips.len() >= limit { if debug { eprintln!("[DEBUG] Límite de IPs alcanzado antes de página {page}"); } pb.finish_with_message("Shodan listo"); break; }
        let url = format!("https://api.shodan.io/shodan/host/search?key={}&query={}&page={}&minify=true", urlencoding::encode(key), urlencoding::encode(query), page);
        if debug { eprintln!("[DEBUG] GET {url}"); }
        let mut need_rate_retry = false;
        let response = client.get(&url).send().await?;
        let status = response.status();
        if debug { eprintln!("[DEBUG] Página {page} status={status}"); }
        if status == StatusCode::TOO_MANY_REQUESTS { need_rate_retry = true; }
        if need_rate_retry {
            eprintln!("[!] 429 en página {page} – backoff 2s");
            sleep(Duration::from_secs(2)).await;
            let response = client.get(&url).send().await?;
            let status2 = response.status();
            if debug { eprintln!("[DEBUG] Retry página {page} status={status2}"); }
            if status2 == StatusCode::TOO_MANY_REQUESTS {
                eprintln!("[!] 429 persistente – salto de página");
                pb.inc(1);
                continue;
            } else if !status2.is_success() {
                let text = response.text().await.unwrap_or_default();
                return Err(anyhow!("Shodan HTTP {}: {}", status2, text));
            } else {
                let v: Value = response.json().await?;
                if debug { eprintln!("[DEBUG] Página {page} matches parseados retry"); }
                if !collect_ips_from_matches(&mut ips, &v, limit) { if debug { eprintln!("[DEBUG] Límite alcanzado dentro de página retry {page}"); } pb.finish_with_message("Shodan listo"); break; }
            }
        } else if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Shodan HTTP {}: {}", status, text));
        } else {
            let v: Value = response.json().await?;
            if debug { eprintln!("[DEBUG] Página {page} matches parseados ok"); }
            if !collect_ips_from_matches(&mut ips, &v, limit) { if debug { eprintln!("[DEBUG] Límite alcanzado dentro de página {page}"); } pb.finish_with_message("Shodan listo"); break; }
        }
        pb.inc(1); sleep(Duration::from_millis(1100)).await; }
    pb.finish_and_clear(); let list_path = out.join("ips.txt"); fs::write(&list_path, ips.iter().cloned().collect::<Vec<_>>().join("\n"))?; Ok(ips.into_iter().collect()) }

fn collect_ips_from_matches(ips: &mut BTreeSet<String>, v: &Value, limit: usize) -> bool {
    let empty = Vec::new();
    let arr = v.get("matches").and_then(|x| x.as_array()).unwrap_or(&empty);
    if arr.is_empty(){ return false; }
    for m in arr { if let Some(ip) = m.get("ip_str").and_then(|x| x.as_str()){ ips.insert(ip.to_string()); if ips.len() >= limit { return false; } } }
    true
}
