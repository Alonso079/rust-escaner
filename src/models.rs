use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpPorts { pub ip: String, pub ports: Vec<u16> }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortDetail { pub port: u16, pub state: String, pub service: Option<String> }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostReport { pub target: String, pub ip: String, pub ports: Vec<PortDetail> }
