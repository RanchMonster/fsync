use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::LazyLock};

use crate::{config_dir, data_dir};
pub static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let config_path = config_dir().join("config.toml");
    if !config_path.exists() {
        let config = Config::default();
        let config_str = toml::to_string(&config).unwrap(); // this should never fail
        std::fs::write(config_path, config_str).expect("Failed to write config file");
        config
    } else {
        let mut buf = String::new();
        let config_str = std::fs::read_to_string(buf).expect("Failed to read config file");
        toml::from_str(&config_str).expect("Failed to parse config file")
    }
});
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub addr: String,
    pub port: u16,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    // TODO: add more vars as needed
}
impl Default for Config {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0".to_string(),
            port: 49152,
            cert_path: None,
            key_path: None,
        }
    }
}
