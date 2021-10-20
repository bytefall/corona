use std::error::Error;
use std::io::{Read, Seek};
use zip::ZipArchive;

use super::Package;

pub struct Bundle {
	pub packages: Vec<Package>,
}

impl Bundle {
	pub fn read(data: impl Read + Seek) -> Result<Bundle, Box<dyn Error>> {
		let mut packages = Vec::new();
		let mut arc = ZipArchive::new(data)?;

		for i in 0..arc.len() {
			// println!("file index {}", i);
			let file = arc
				.by_index(i)
				.unwrap_or_else(|_| panic!("Failed to get a file by_index({})", i));

			let path = file.sanitized_name();

			if path.extension().map_or("", |x| x.to_str().unwrap_or("")) == "pkt" {
				if let Some(_name) = path.to_str() {
					// println!("{}", name); // 5b1e8f04.pkt
					packages.push(Package::read(file)?);
				}
			}
		}

		Ok(Self { packages })
	}
}
