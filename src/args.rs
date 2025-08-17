use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Clone)]
#[command(name = "shodan-pipeline", version)]
/// Pipeline completo: keywords -> Shodan -> RustScan -> Nmap -> reglas dinámicas
pub struct Args {
    /// API key de Shodan (si no, leerá SHODAN_API_KEY)
    #[arg(long, env = "SHODAN_API_KEY")]
    pub key: Option<String>,

    /// Modo depuración (prints detallados)
    #[arg(long, default_value_t = false)]
    pub debug: bool,

    /// Carpeta de trabajo para outputs (XML, logs, csv, etc.)
    #[arg(long, default_value = "out")]
    pub out: PathBuf,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Clone)]
pub enum Cmd {
    /// Ejecuta TODO: keywords -> Shodan (N páginas) -> (opcional RustScan) -> Nmap -> reglas -> CSV
    Full {
        /// Palabras clave separadas por coma. Ej: 'chile,.cl,muni'
        #[arg(long)]
        keywords: String,
        /// Máximo de IPs a recolectar desde Shodan
    #[arg(long, default_value_t = 5)]
        limit: usize,
    /// Activa el modo Hunt (búsqueda iterativa por lotes)
    #[arg(long, default_value_t = false)]
    hunt: bool,
    /// Cuántos hosts interesantes se necesitan (decrementa 5->4->..->0)
    #[arg(long, default_value_t = 5)]
    hunt_needed: usize,
    /// Umbral mínimo de puertos abiertos (tras filtros) para marcar un host como interesante
    #[arg(long, default_value_t = 3)]
    hunt_min_open: usize,
    /// Tamaño del lote (cantidad de IPs por batch de escaneo)
    #[arg(long, default_value_t = 5)]
    hunt_batch: usize,
    /// Objetivo de hosts "interesantes" (>= min puertos abiertos). Si >0 activa modo adaptativo incremental.
    #[arg(long, default_value_t = 0)]
    interesting_target: usize,
    /// Umbral mínimo de puertos abiertos para que un host se considere interesante.
    #[arg(long, default_value_t = 2)]
    interesting_min_open: usize,
        /// Páginas a pedir a Shodan (1..N), por defecto 20
        #[arg(long, default_value_t = 20)]
        pages: usize,
        /// Archivo opcional con objetivos (IP o dominio), uno por línea
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Si se define, Nmap ignora RustScan y escanea estos puertos fijos (matriz), ej: "22,80,443"
        #[arg(long)]
        fixed_ports: Option<String>,
        /// Concurrencia para RustScan (IPs simultáneas)
        #[arg(long, default_value_t = 32)]
        rs_concurrency: usize,
        /// Concurrencia para Nmap (IPs simultáneas)
        #[arg(long, default_value_t = 3)]
        nmap_concurrency: usize,
        /// Extra para Nmap (ej: "-sV -sC -Pn"). Valor por defecto seguro sin root.
    #[arg(long, default_value = "-sT -sV -Pn --version-intensity 5 --max-retries 2")]
    nmap_extra: String,
        /// Archivo YAML de reglas dinámicas (puerto/servicio -> comandos)
        #[arg(long, default_value = "rules.yaml")]
        rules: PathBuf,
        /// Reanudar: si existe out/<IP>/nmap.xml no vuelve a ejecutar Nmap
        #[arg(long, default_value_t = false)]
        resume: bool,
    #[arg(long, default_value_t = true)]
    hide_tcpwrapped: bool,
    #[arg(long, default_value_t = true)]
    only_open: bool,
    #[arg(long, default_value_t = false)]
    confirm_wrapped: bool,
    },
    /// Solo Shodan -> ips.txt (y sale)
    Intel { #[arg(long)] keywords: String, #[arg(long, default_value_t = 5)] limit: usize, #[arg(long, default_value_t = 20)] pages: usize },
    /// Solo RustScan sobre un archivo de objetivos (IPs/dominios). Guarda rustscan.jsonl
    Rustscan { #[arg(long)] input_targets: PathBuf, #[arg(long, default_value_t = 1500)] timeout_ms: u64, #[arg(long, default_value_t = 4500)] batch: u32, #[arg(long, default_value_t = 32)] concurrency: usize },
    /// Solo Nmap desde un JSONL con {ip,ports:[...]} (o con --fixed-ports)
    Nmap { #[arg(long)] input_jsonl: Option<PathBuf>, #[arg(long)] fixed_ports: Option<String>, #[arg(long, default_value = "-sT -sV -Pn --version-intensity 5 --max-retries 2")] nmap_extra: String, #[arg(long, default_value_t = 3)] concurrency: usize, #[arg(long, default_value_t = false)] resume: bool, #[arg(long, default_value_t = true)] hide_tcpwrapped: bool, #[arg(long, default_value_t = true)] only_open: bool, #[arg(long, default_value_t = false)] confirm_wrapped: bool },
    /// Configurar o mostrar la API key persistente (~/.config/.../api_key)
    Config {
        /// Guarda la clave indicada y termina
        #[arg(long)]
        set: Option<String>,
        /// Muestra la ruta del archivo donde se almacena
        #[arg(long, default_value_t = false)]
        show_path: bool,
    }
    ,
    /// Limpia artefactos (out/* y cache incremental si se desea)
    Clean {
        /// También borrar target/ (recompilación completa)
        #[arg(long, default_value_t = false)]
        deep: bool,
    }
}
