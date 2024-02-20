use clap::Parser;

#[macro_use]
extern crate serde_derive;

mod cfg;
mod cli;
mod core;
mod ftn;
mod store;
mod tosser;

use self::cli::Args;

fn main() {
    let args = Args::parse();

    let mut cfg_path = dirs::config_dir().unwrap();
    cfg_path.push("corona");
    cfg_path.push("corona.toml");

    let cfg = match cfg::Config::new(&cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Cannot open config file {}, reason: {e}", cfg_path.display());
            return;
        }
    };

    // TODO: check that there is some space left on drive

    match args {
        Args::Toss => {
            if let Err(e) = tosser::toss(&cfg) {
                eprintln!("Toss failed: {e}");
            }
        }
    }
}
