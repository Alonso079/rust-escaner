use serde::Deserialize;
use std::fs;
use anyhow::Result;

#[derive(Debug, Deserialize)]
pub struct Rules { pub rules: Vec<Rule> }

#[derive(Debug, Deserialize)]
pub struct Rule { pub name: String, #[serde(default)] pub ports: Vec<u16>, #[serde(default)] pub service_regex: Option<String>, #[serde(default)] pub cmds: Vec<String> }

pub fn load_rules(path: &std::path::Path) -> Result<Rules> { let text = fs::read_to_string(path)?; let r: Rules = serde_yaml::from_str(&text)?; Ok(r) }
