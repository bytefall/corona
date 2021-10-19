use std::error::Error;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
	pub inbound: Option<Inbound>,
	pub msgbase: Option<Msgbase>,
}

#[derive(Debug, Deserialize)]
pub struct Inbound {
	pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Msgbase {
	pub path: Option<String>,
}

impl Config {
	pub fn new(path: &Path) -> Result<Config, Box<dyn Error>> {
		Ok(toml::from_slice(&std::fs::read(path)?)?)
	}
}
