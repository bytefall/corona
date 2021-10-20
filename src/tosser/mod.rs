use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::cfg::Config;
use crate::core::Area;
use crate::store::MessageBase;

enum InboundType {
	Package,
	Bundle,
}

pub fn toss(config: &Config) -> Result<(), Box<dyn Error>> {
	let inbound = config.inbound.as_ref().unwrap().path.as_ref().unwrap();
	let msgbase = Path::new(config.msgbase.as_ref().unwrap().path.as_ref().unwrap());

	let mut inbound: Vec<_> = fs::read_dir(inbound)?
		.filter_map(|e| e.ok())
		.filter_map(|e| {
			if let Ok(m) = e.metadata() {
				Some((e.path(), m))
			} else {
				None
			}
		})
		.filter(|(_, m)| m.is_file())
		.filter(|(_, m)| m.len() > 64)
		.filter_map(|(p, m)| {
			let (name, ext) = file_name_ext(&p);

			if name.is_empty() || ext.len() != 3 {
				return None;
			}

			match (&ext[..2], &ext[2..]) {
				("pk", "t") => Some((p, InboundType::Package, m)),
				("su" | "mo" | "tu" | "we" | "th" | "fr" | "sa", _) => Some((p, InboundType::Bundle, m)),
				_ => None,
			}
		})
		.filter_map(|(p, t, m)| {
			if let Ok(tmod) = m.modified() {
				Some((p, t, tmod))
			} else {
				None
			}
		})
		.collect();

	inbound.sort_by(|(_, _, mx), (_, _, my)| mx.cmp(my));

	let mut bases = HashMap::new();

	for (path, ty, _) in inbound {
		match File::open(&path) {
			Ok(file) => {
				match ty {
					InboundType::Package => {
						println!("tossing {:?}", path);

						fn get_messages(file: &File) -> Result<Vec<crate::core::Message>, Box<dyn Error>> {
							crate::core::messages_from(crate::ftn::Package::read(file)?)
						}

						match get_messages(&file) {
							Ok(msgs) => {
								toss_messages(msgs, msgbase, &mut bases)?;

								// remove package if everything is ok
								fs::remove_file(&path)?;
							}
							Err(e) => {
								bad_mail(&path, e)?;
							}
						}
					}
					InboundType::Bundle => {
						println!("tossing {:?}", path);

						match crate::ftn::Bundle::read(file) {
							Ok(bundle) => {
								for pkg in bundle.packages {
									// TODO: handle the case when one PKG in a bundle is corrupted, while others - don't
									toss_messages(crate::core::messages_from(pkg)?, msgbase, &mut bases)?;
								}

								// remove bundle if everything is ok
								fs::remove_file(&path)?;
							}
							Err(e) => {
								bad_mail(&path, e)?;
							}
						}
					}
				}
			}
			Err(e) => {
				eprintln!("Failed to open \"{}\", reason: {}", file_name_ext(&path).0, e);
			}
		}
	}

	Ok(())
}

fn file_name_ext(path: &Path) -> (&str, &str) {
	(
		path.file_name().map_or("", |x| x.to_str().unwrap_or("")),
		path.extension().map_or("", |x| x.to_str().unwrap_or("")),
	)
}

fn bad_mail(path: &Path, err: Box<dyn Error>) -> Result<(), Box<dyn Error>> {
	let (name, ext) = file_name_ext(path);

	eprintln!("Failed to read \"{}\", reason: {}", name, err);

	fs::rename(&path, Path::new(&path).with_extension(ext.to_string() + ".bad"))?;

	Ok(())
}

fn toss_messages(
	inbound: Vec<crate::core::Message>,
	msgbase: &Path,
	bases: &mut HashMap<PathBuf, MessageBase>,
) -> Result<(), Box<dyn Error>> {
	for msg in inbound {
		let db_path = match msg.area {
			Area::Netmail => msgbase.join("netmail"),
			Area::Echomail(ref name) => msgbase.join(&name.to_ascii_lowercase()),
		};

		let mb = bases
			.entry(db_path.clone())
			.or_insert_with(|| MessageBase::open(&db_path).unwrap());

		mb.toss(msg)?;
	}

	Ok(())
}
