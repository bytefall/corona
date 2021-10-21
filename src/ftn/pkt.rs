use chrono::{NaiveDate, NaiveDateTime};
use podio::{BigEndian, LittleEndian, ReadPodExt};
use std::error::Error;
use std::fmt;
use std::io::{BufRead, BufReader, Read};

#[derive(Debug)]
pub struct Address {
	pub zone: u16,
	pub net: u16,
	pub node: u16,
	pub point: u16,
}

#[derive(Debug)]
pub struct User {
	pub address: Address,
	pub name: Vec<u8>,
}

#[derive(Debug)]
pub struct Message {
	pub posted: Vec<u8>,
	pub from: User,
	pub to: User,
	pub flags: u16,
	pub subj: Vec<u8>,
	pub text: Vec<u8>,
}

#[derive(Debug)]
pub struct Package {
	orig: Address,
	dest: Address,
	pub created: NaiveDateTime,
	password: String,
	rate: u16,
	ver: u16,
	prod_code: u8,
	serial_no: u8,
	aux_net: u16,
	cap_word: u16,
	hi_product_code: u8,
	minor_product_rev: u8,
	pub messages: Vec<Message>,
}

#[derive(Debug)]
pub enum PackageError {
	InvalidDate { year: u16, month: u16, day: u16 },
	InvalidTime { hour: u16, minute: u16, second: u16 },
}

impl PackageError {
	fn date(year: u16, month: u16, day: u16) -> Self {
		PackageError::InvalidDate { year, month, day }
	}

	fn time(hour: u16, minute: u16, second: u16) -> Self {
		PackageError::InvalidTime { hour, minute, second }
	}
}

impl fmt::Display for PackageError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl Error for PackageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(self)
	}
}

const POSTED_DATE_LEN: usize = 19;

impl Package {
	pub fn read(data: impl Read) -> Result<Package, Box<dyn Error>> {
		let mut r = BufReader::new(data);

		let orig_node = r.read_u16::<LittleEndian>()?;
		let dest_node = r.read_u16::<LittleEndian>()?;

		let year = r.read_u16::<LittleEndian>()?;
		let month = r.read_u16::<LittleEndian>()? + 1;
		let day = r.read_u16::<LittleEndian>()?;
		let hour = r.read_u16::<LittleEndian>()?;
		let minute = r.read_u16::<LittleEndian>()?;
		let second = r.read_u16::<LittleEndian>()?;

		let created = NaiveDate::from_ymd_opt(year.into(), month.into(), day.into())
			.ok_or_else(|| Box::new(PackageError::date(year, month, day)))?
			.and_hms_opt(hour.into(), minute.into(), second.into())
			.ok_or_else(|| Box::new(PackageError::time(hour, minute, second)))?;

		let rate = r.read_u16::<LittleEndian>()?;
		let ver = r.read_u16::<LittleEndian>()?;

		let orig_net = r.read_u16::<LittleEndian>()?;
		let dest_net = r.read_u16::<LittleEndian>()?;

		let prod_code = r.read_u8()?;
		let serial_no = r.read_u8()?;

		let password = ReadPodExt::read_exact(&mut r, 8)?;
		let password = if let Some(x) = password.iter().position(|&x| x == 0) {
			password[..x].to_vec()
		} else {
			password
		};
		let password = String::from_utf8(password)?;

		let orig_zone = r.read_u16::<LittleEndian>()?;
		let dest_zone = r.read_u16::<LittleEndian>()?;

		let aux_net = r.read_u16::<LittleEndian>()?;

		let _cap_word_copy = r.read_u16::<BigEndian>()?;

		let hi_product_code = r.read_u8()?;
		let minor_product_rev = r.read_u8()?;

		let cap_word = r.read_u16::<LittleEndian>()?;

		r.read_u32::<LittleEndian>()?; // zone info

		let orig_point = r.read_u16::<LittleEndian>()?;
		let dest_point = r.read_u16::<LittleEndian>()?;

		r.read_u32::<LittleEndian>()?; // product specific data

		let mut messages = Vec::new();

		while let Ok(w) = r.read_u16::<LittleEndian>() {
			if w != 2 {
				let mut extra_bytes = Vec::new();

				match r.read_to_end(&mut extra_bytes) {
					Ok(0) => break, // there are no extra bytes
					Ok(size) => eprintln!("There are {:?} byte(s) of unknown data at the end of pkt file!", size), // TODO: PackageError(extra_bytes)
					Err(e) => return Err(Box::new(e)),
				}
			}

			let from_node = r.read_u16::<LittleEndian>()?;
			let to_node = r.read_u16::<LittleEndian>()?;

			let from_net = r.read_u16::<LittleEndian>()?;
			let to_net = r.read_u16::<LittleEndian>()?;

			let flags = r.read_u16::<LittleEndian>()?;

			let _ = r.read_u16::<LittleEndian>()?;

			fn read_excl_zero(r: &mut BufReader<impl Read>, v: &mut Vec<u8>) -> std::io::Result<usize> {
				let len = r.read_until(0, v)?;

				match v.last() {
					Some(&0) => {
						v.pop();

						Ok(len - 1)
					}
					_ => Ok(len),
				}
			}

			let mut posted = Vec::new();
			let mut to_name = Vec::new();
			let mut from_name = Vec::new();
			let mut subj = Vec::new();
			let mut text = Vec::new();

			let posted_len = read_excl_zero(&mut r, &mut posted)?;

			if posted_len != POSTED_DATE_LEN {
				eprintln!(
					"Warning: posted date length {} != {}. Actual value: {:02X?}",
					posted_len, POSTED_DATE_LEN, posted
				);

				posted.clear();

				for _ in posted_len..POSTED_DATE_LEN {
					let extra = r.read_u8()?;

					if extra != 0 {
						to_name.push(extra); // oops, bring it back
						break;
					}
				}
			}

			read_excl_zero(&mut r, &mut to_name)?;
			read_excl_zero(&mut r, &mut from_name)?;
			read_excl_zero(&mut r, &mut subj)?;
			read_excl_zero(&mut r, &mut text)?;

			messages.push(Message {
				posted,
				from: User {
					address: Address {
						zone: orig_zone,
						net: from_net,
						node: from_node,
						point: 0,
					},
					name: from_name,
				},
				to: User {
					address: Address {
						zone: dest_zone,
						net: to_net,
						node: to_node,
						point: 0,
					},
					name: to_name,
				},
				flags,
				subj,
				text,
			});
		}

		Ok(Self {
			orig: Address {
				zone: orig_zone,
				net: orig_net,
				node: orig_node,
				point: orig_point,
			},
			dest: Address {
				zone: dest_zone,
				net: dest_net,
				node: dest_node,
				point: dest_point,
			},
			created,
			password,
			rate,
			ver,
			prod_code,
			serial_no,
			aux_net,
			cap_word,
			hi_product_code,
			minor_product_rev,
			messages,
		})
	}
}

#[cfg(test)]
mod test {
	use super::Package;
	use std::io::Cursor;

	fn create_pkt() -> Vec<u8> {
		let mut data = Vec::new();

		add_header(&mut data);
		add_message(&mut data);
		end_message(&mut data);

		data
	}

	const ORIG_ZONE: u16 = 1;
	const ORIG_NET: u16 = 5020;
	const ORIG_NODE: u16 = 100;
	const ORIG_POINT: u16 = 300;

	const DEST_ZONE: u16 = 2;
	const DEST_NET: u16 = 5030;
	const DEST_NODE: u16 = 200;
	const DEST_POINT: u16 = 400;

	const DT_YEAR: u16 = 1999;
	const DT_MONTH: u16 = 1;
	const DT_DAY: u16 = 2;
	const DT_HOUR: u16 = 23;
	const DT_MINUTE: u16 = 31;
	const DT_SECOND: u16 = 40;

	const RATE: u16 = 0;
	const VER: u16 = 2;

	const PROD_CODE: u8 = 255;
	const SERIAL_NO: u8 = 1;

	const PASSWORD: &str = "pwdpwd\0\0";

	const AUX_NET: u16 = 0;
	const CAP_WORD_X: u16 = 256;

	const HIGH_PROD_CODE: u8 = 16;
	const MINOR_PROD_REV: u8 = 9;

	const CAP_WORD: u16 = 1;

	const ORIG_ZONE_INFO: u16 = 1;
	const DEST_ZONE_INFO: u16 = 2;

	const PROD_DATA: u32 = 0;

	fn add_header(data: &mut Vec<u8>) {
		data.extend_from_slice(&ORIG_NODE.to_le_bytes());
		data.extend_from_slice(&DEST_NODE.to_le_bytes());

		data.extend_from_slice(&DT_YEAR.to_le_bytes());
		data.extend_from_slice(&DT_MONTH.to_le_bytes());
		data.extend_from_slice(&DT_DAY.to_le_bytes());
		data.extend_from_slice(&DT_HOUR.to_le_bytes());
		data.extend_from_slice(&DT_MINUTE.to_le_bytes());
		data.extend_from_slice(&DT_SECOND.to_le_bytes());

		data.extend_from_slice(&RATE.to_le_bytes());
		data.extend_from_slice(&VER.to_le_bytes());

		data.extend_from_slice(&ORIG_NET.to_le_bytes());
		data.extend_from_slice(&DEST_NET.to_le_bytes());

		data.push(PROD_CODE);
		data.push(SERIAL_NO);

		data.extend_from_slice(PASSWORD.as_bytes());

		data.extend_from_slice(&ORIG_ZONE.to_le_bytes());
		data.extend_from_slice(&DEST_ZONE.to_le_bytes());

		data.extend_from_slice(&AUX_NET.to_le_bytes());

		data.extend_from_slice(&CAP_WORD_X.to_le_bytes());

		data.push(HIGH_PROD_CODE);
		data.push(MINOR_PROD_REV);

		data.extend_from_slice(&CAP_WORD.to_le_bytes());

		data.extend_from_slice(&ORIG_ZONE_INFO.to_le_bytes());
		data.extend_from_slice(&DEST_ZONE_INFO.to_le_bytes());

		data.extend_from_slice(&ORIG_POINT.to_le_bytes());
		data.extend_from_slice(&DEST_POINT.to_le_bytes());

		data.extend_from_slice(&PROD_DATA.to_le_bytes());
	}

	fn add_message(data: &mut Vec<u8>) {
		data.extend_from_slice(&2u16.to_le_bytes());

		data.extend_from_slice(&40u16.to_le_bytes()); // from_node
		data.extend_from_slice(&40u16.to_le_bytes()); // to_node

		data.extend_from_slice(&40u16.to_le_bytes()); // from_net
		data.extend_from_slice(&40u16.to_le_bytes()); // to_net

		data.extend_from_slice(&40u16.to_le_bytes()); // flags

		data.extend_from_slice(&0u16.to_le_bytes()); // unused

		data.extend_from_slice("28 Feb 20  14:00:18\0".as_bytes()); // posted
		data.extend_from_slice("All\0".as_bytes()); // to_name
		data.extend_from_slice("John Doe\0".as_bytes()); // from_name
		data.extend_from_slice("Ping\0".as_bytes()); // subj
		data.extend_from_slice("Pong\0".as_bytes()); // text
	}

	fn end_message(data: &mut Vec<u8>) {
		data.extend_from_slice(&0u16.to_le_bytes());
	}

	#[test]
	fn pkg_has_orig_addr() {
		let mem = Cursor::new(create_pkt());
		let pkg = Package::read(mem).unwrap();

		assert_eq!(pkg.orig.zone, ORIG_ZONE);
		assert_eq!(pkg.orig.net, ORIG_NET);
		assert_eq!(pkg.orig.node, ORIG_NODE);
		assert_eq!(pkg.orig.point, ORIG_POINT);
	}
}
