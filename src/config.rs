use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::{fs, path::PathBuf};

pub fn config_file() -> Result<PathBuf> {
    let proj = ProjectDirs::from("io", "shodan", "shodan-pipeline")
        .context("No pude resolver el directorio de configuración")?;
    let dir = proj.config_dir();
    fs::create_dir_all(dir)?;
    Ok(dir.join("api_key"))
}

pub fn save_key(key: &str) -> Result<PathBuf> {
    let path = config_file()?;
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        write!(f, "{}", key.trim())?;
    }
    #[cfg(windows)]
    {
        fs::write(&path, key.trim())?;
    }
    Ok(path)
}

pub fn load_key_from_file() -> Option<String> {
    let path = config_file().ok()?;
    let s = fs::read_to_string(path).ok()?;
    let k = s.trim().to_string();
    if k.is_empty() { None } else { Some(k) }
}
