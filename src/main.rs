#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate rusqlite;

mod cfg;
mod core;
mod ftn;
mod store;
mod tosser;

fn main() {
	let mut cfg_path = dirs::config_dir().unwrap();
	cfg_path.push("corona");
	cfg_path.push("corona.toml");

	let cfg = match cfg::Config::new(&cfg_path) {
		Ok(cfg) => cfg,
		Err(e) => {
			eprintln!("Cannot open config file {}, reason: {}", cfg_path.display(), e);
			return;
		}
	};

	// TODO: check that there is some space left on drive

	if let Err(e) = tosser::toss(&cfg) {
		eprintln!("Toss failed: {}", e);
	}
}
