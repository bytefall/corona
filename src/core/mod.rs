use chrono::{NaiveDate, NaiveDateTime};
use encoding::{all::IBM866, DecoderTrap, Encoding};
use std::error::Error;
use std::num::{IntErrorKind, ParseIntError};
use std::str::FromStr;

/// Fidonet address according to FRL-1002
#[derive(Eq, PartialEq, Debug)]
pub struct Address {
	pub zone: u16,
	pub net: u16,
	pub node: u16,
	pub point: u16,
	pub domain: Option<String>,
}

impl Address {
	pub fn empty() -> Self {
		Self::full(0, 0, 0, 0, None)
	}

	/*pub fn new_3d(zone: u16, net: u16, node: u16) -> Self {
		Self::full(zone, net, node, 0, None)
	}*/

	pub fn new_4d(zone: u16, net: u16, node: u16, point: u16) -> Self {
		Self::full(zone, net, node, point, None)
	}

	/*pub fn new_5d(zone: u16, net: u16, node: u16, point: u16, domain: String) -> Self {
		Self::full(zone, net, node, point, Some(domain))
	}*/

	fn full(zone: u16, net: u16, node: u16, point: u16, domain: Option<String>) -> Self {
		Self {
			zone,
			net,
			node,
			point,
			domain,
		}
	}
}

impl From<crate::ftn::Address> for Address {
	fn from(a: crate::ftn::Address) -> Self {
		Self::new_4d(a.zone, a.net, a.node, a.point)
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseAddressError {
	InvalidFormat,
	Overflow,
}

impl std::fmt::Display for ParseAddressError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidFormat => "Format is not valid. It should be either 3D, 4D or 5D.",
			Self::Overflow => "Number is too large to fit in target type.",
		}
		.fmt(f)
	}
}

impl FromStr for Address {
	type Err = ParseAddressError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		#[derive(PartialEq)]
		enum Tag {
			Zone,
			Net(usize),
			Node(usize),
			Point(usize),
			Domain(usize),
		}

		use Tag::*;

		let map_parse_int_err = |err: ParseIntError| match err.kind() {
			IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => Self::Err::Overflow,
			_ => Self::Err::InvalidFormat,
		};

		let mut a = Self::empty();
		let mut tag = Zone;
		let mut iter = s.char_indices();

		loop {
			let chr = iter.next();

			match (&tag, chr) {
				(Zone, Some((i, ':'))) => {
					a.zone = s[..i].parse().map_err(map_parse_int_err)?;
					tag = Net(i + 1);
				}
				(Net(start), Some((i, '/'))) => {
					a.net = s[*start..i].parse().map_err(map_parse_int_err)?;
					tag = Node(i + 1);
				}
				(Node(start), Some((i, '.'))) => {
					a.node = s[*start..i].parse().map_err(map_parse_int_err)?;
					tag = Point(i + 1);
				}
				(Node(start), None) => {
					a.node = s[*start..].parse().map_err(map_parse_int_err)?;
				}
				(Node(start), Some((i, '@'))) => {
					a.node = s[*start..i].parse().map_err(map_parse_int_err)?;
					tag = Domain(i + 1);
				}
				(Point(start), Some((i, '@'))) => {
					a.point = s[*start..i].parse().map_err(map_parse_int_err)?;
					tag = Domain(i + 1);
				}
				(Point(start), None) => {
					a.point = s[*start..].parse().map_err(map_parse_int_err)?;
				}
				(Domain(start), None) => {
					a.domain = Some(s[*start..].to_string());
				}
				(_, None) => {
					return Err(Self::Err::InvalidFormat);
				}
				_ => {}
			}

			if chr.is_none() {
				break;
			}
		}

		Ok(a)
	}
}

#[derive(Debug)]
pub struct User {
	pub addr: Address,
	pub name: String,
	pub ext_addr: Option<String>,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Area {
	Netmail,
	Echomail(String),
}

#[derive(Debug)]
pub struct ControlLines {
	pub pid: Option<String>,
	pub tid: Option<String>,
	pub tzutc: Option<String>,
	pub seen_by: Option<Vec<NetNodePair>>,
	pub path: Option<Vec<NetNodePair>>,
	pub custom: Option<Vec<String>>,
}

impl ControlLines {
	fn empty() -> Self {
		Self {
			pid: None,
			tid: None,
			tzutc: None,
			seen_by: None,
			path: None,
			custom: None,
		}
	}
}

#[derive(Debug)]
pub struct Message {
	pub area: Area,
	pub posted: NaiveDateTime,
	pub from: User,
	pub to: User,
	pub flags: u16,
	pub msgid_serial: u32,
	pub reply_serial: Option<u32>,
	pub msgid_addr: Option<String>,
	pub reply_addr: Option<String>,
	pub subj: String,
	pub body: String,
	pub tear_line: String,
	pub origin: String,
	pub kludges: ControlLines,
}

type TokenPair<'a> = (Token, &'a str);

pub fn messages_from(pkg: crate::ftn::Package) -> Result<Vec<Message>, Box<dyn Error>> {
	let mut ret = Vec::new();

	for m in pkg.messages {
		let posted = String::from_utf8(m.posted)?;
		let posted = match parse_ftn_datetime(&posted) {
			Ok(dt) => dt,
			Err(e) => {
				eprintln!(
					"Warning: failed to parse posted date \"{}\", reason: \"{:?}\". Falling back to pkg create date.",
					&posted, e
				);
				pkg.created
			}
		};

		let mut msg = Message {
			area: Area::Netmail,
			posted,
			from: User {
				addr: m.from.address.into(),
				name: IBM866.decode(&m.from.name, DecoderTrap::Strict)?,
				ext_addr: None,
			},
			to: User {
				addr: m.to.address.into(),
				name: IBM866.decode(&m.to.name, DecoderTrap::Strict)?,
				ext_addr: None,
			},
			flags: m.flags,
			msgid_serial: 0,
			reply_serial: None,
			msgid_addr: None,
			reply_addr: None,
			subj: IBM866.decode(&m.subj, DecoderTrap::Strict)?, // DecoderTrap::Ignore
			body: String::with_capacity(m.text.len()),
			tear_line: String::new(),
			origin: String::new(),
			kludges: ControlLines::empty(),
		};

		let text = IBM866.decode(&m.text, DecoderTrap::Strict)?.replace('\r', "\n");

		parse_tokens(&tokenize_msg_body(&text)?, &mut msg)?;

		ret.push(msg);
	}

	Ok(ret)
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum Token {
	Area,            // AREA:
	MsgId,           // MSGID:
	Reply,           // REPLY:
	Pid,             // PID:
	Tid,             // TID:
	TzUtc,           // TZUTC:
	TearLine(usize), // ---
	Origin(usize),   // * Origin:
	SeenBy(usize),   // SEEN-BY:
	Path,            // PATH:
	Kludge,          // unknown kludge
	Paragraph,
}

const NEWLINE: char = '\n';
const START_OF_HEADING: char = '\u{1}';
// const ZERO: char = '\0';

const MSGID: &str = "MSGID: ";
const REPLY: &str = "REPLY: ";
const PID: &str = "PID: ";
const TID: &str = "TID: ";
const TZUTC: &str = "TZUTC: ";
const PATH: &str = "PATH: ";

const REPLYADDR: &str = "REPLYADDR: ";
const REPLYADDR_V2: &str = "REPLYADDR ";
const REPLYTO: &str = "REPLYTO: ";
const REPLYTO_V2: &str = "REPLYTO ";

const INTL: &str = "INTL ";
const FMPT: &str = "FMPT ";
const TOPT: &str = "TOPT ";

const AREA: &str = "AREA:";
const TEAR_LINE: &str = "--- ";
const TEAL_LINE_V2: &str = "---";
const ORIGIN: &str = " * Origin: ";
const SEEN_BY: &str = "SEEN-BY: ";

// &nbsp; is treated as \u{a0}
fn tokenize_msg_body(text: &str) -> Result<Vec<TokenPair<'_>>, Box<dyn Error>> {
	let mut tokens = Vec::new();

	for par in text.split(NEWLINE) {
		let token = if par.starts_with(TEAR_LINE) {
			Token::TearLine(TEAR_LINE.len())
		} else if par == TEAL_LINE_V2 {
			Token::TearLine(TEAL_LINE_V2.len())
		} else if par.starts_with(ORIGIN) {
			Token::Origin(ORIGIN.len())
		} else if par.starts_with(SEEN_BY) {
			Token::SeenBy(SEEN_BY.len())
		} else {
			Token::Paragraph
		};

		for (pos, sub) in par.split(START_OF_HEADING).enumerate() {
			if pos == 0 {
				// add leading piece
				tokens.push((token.clone(), sub));
			} else {
				// skip newline between kludges
				if tokens.last() == Some(&(Token::Paragraph, "")) {
					tokens.pop();
				}

				let (token, skip) = if sub.starts_with(MSGID) {
					(Token::MsgId, MSGID.len())
				} else if sub.starts_with(REPLY) {
					(Token::Reply, REPLY.len())
				} else if sub.starts_with(PID) {
					(Token::Pid, PID.len())
				} else if sub.starts_with(TID) {
					(Token::Tid, TID.len())
				} else if sub.starts_with(TZUTC) {
					(Token::TzUtc, TZUTC.len())
				} else if sub.starts_with(PATH) {
					(Token::Path, PATH.len())
				} else {
					(Token::Kludge, 0)
				};

				tokens.push((token, &sub[skip..]));
			}
		}
	}

	// remove last empty paragraph (which is most likely after TearLine, Origin or PATH)
	if let Some((Token::Paragraph, "")) = tokens.last() {
		tokens.pop();
	}

	let mut has_tear_line = false;
	let mut has_origin = false;

	// origins or SEEN-BYs prior the last origin are treated as a normal text
	for (t, _) in tokens
		.iter_mut()
		.rev()
		.filter(|(t, _)| matches!(t, Token::TearLine(_) | Token::Origin(_) | Token::SeenBy(_)))
	{
		match t {
			Token::TearLine(_) if has_origin && has_tear_line => {
				*t = Token::Paragraph;
			}
			Token::TearLine(_) if !has_tear_line => {
				has_tear_line = true;
			}
			Token::Origin(_) if has_origin => {
				*t = Token::Paragraph;
			}
			Token::Origin(_) if !has_origin => {
				has_origin = true;
			}
			Token::SeenBy(_) if has_origin => {
				*t = Token::Paragraph;
			}
			_ => {}
		}
	}

	// locate first non-empty paragraph to get AREA:
	if let Some((t, s)) = tokens.iter_mut().find(|(t, s)| t == &Token::Paragraph && !s.is_empty()) {
		if s.starts_with(AREA) {
			*t = Token::Area;
			*s = &s[AREA.len()..];
		}
	}

	// for pair in &tokens {
	// 	println!("{:?}\t\t{:?}", pair.0, pair.1);
	// }

	Ok(tokens)
}

fn parse_tokens(tokens: &[TokenPair], msg: &mut Message) -> Result<(), Box<dyn Error>> {
	let mut native_from = None;
	let mut native_to = None;

	for (t, s) in tokens {
		match t {
			Token::Area => {
				msg.area = Area::Echomail(s.trim().to_string());
			}
			Token::MsgId => {
				if let Ok(id) = MessageId::from_str(s.trim()) {
					msg.msgid_serial = id.serial;

					match id.addr {
						AddressKind::Native(a) => native_from = Some(a),
						AddressKind::External(a) => msg.msgid_addr = Some(a),
					}
				} else {
					eprintln!("MSGID parse fail: {}", s);
				}
			}
			Token::Reply => {
				if let Ok(id) = MessageId::from_str(s.trim()) {
					msg.reply_serial = Some(id.serial);

					match id.addr {
						AddressKind::Native(a) => native_to = Some(a),
						AddressKind::External(a) => msg.reply_addr = Some(a),
					}
				} else {
					eprintln!("REPLY parse fail: {}", s);
				}
			}
			Token::Pid => {
				msg.kludges.pid = Some(s.to_string());
			}
			Token::Tid => {
				msg.kludges.tid = Some(s.to_string());
			}
			Token::TzUtc => {
				msg.kludges.tzutc = Some(s.to_string());
			}
			Token::TearLine(skip) => {
				msg.tear_line.push_str(&s[*skip..]);
			}
			Token::Origin(skip) => {
				msg.origin.push_str(&s[*skip..]);
			}
			Token::SeenBy(skip) => match &mut parse_net_node_pairs(s[*skip..].trim()) {
				Ok(v) => msg.kludges.seen_by.get_or_insert(Vec::new()).append(v),
				Err(_) => eprintln!("SEEN-BY parse fail: {}", s),
			},
			Token::Path => match &mut parse_net_node_pairs(s.trim()) {
				Ok(v) => msg.kludges.path.get_or_insert(Vec::new()).append(v),
				Err(_) => eprintln!("PATH parse fail: {}", s),
			},
			Token::Kludge => {
				if let Some(suffix) = s.strip_prefix(REPLYADDR) {
					msg.from.ext_addr = Some(suffix.to_string());
				} else if let Some(suffix) = s.strip_prefix(REPLYADDR_V2) {
					msg.from.ext_addr = Some(suffix.to_string());
				} else {
					if let Some(suffix) = s.strip_prefix(REPLYTO) {
						if let Ok((a, _name)) = parse_replyto(suffix.trim()) {
							native_from = Some(a);
						}
					} else if let Some(suffix) = s.strip_prefix(REPLYTO_V2) {
						if let Ok((a, _name)) = parse_replyto(suffix.trim()) {
							native_from = Some(a);
						}
					}

					msg.kludges.custom.get_or_insert(Vec::new()).push(s.to_string());
				}
			}
			Token::Paragraph => {
				msg.body.push_str(s);
				msg.body.push(NEWLINE);
			}
		}
	}

	// trim NEWLINE from the last Token::Paragraph
	if msg.body.ends_with(NEWLINE) {
		msg.body.pop();
	}

	// as a last resort - parse address from Origin
	if native_from.is_none() && !msg.origin.is_empty() {
		let mut i = msg.origin.char_indices().rev().filter(|(_, c)| c == &'(' || c == &')');

		match (i.next(), i.next()) {
			(Some((end, ')')), Some((start, '('))) if start + 3 < end => {
				if let Ok(a) = Address::from_str(&msg.origin[start + 1..end]) {
					native_from = Some(a);
				}
			}
			_ => {}
		}
	}

	// set FROM
	if let Some(a) = native_from {
		msg.from.addr = a;
	}

	// set TO
	msg.to.addr = if let Some(a) = native_to { a } else { Address::empty() };

	// why not?
	if msg.reply_serial.is_none() && msg.to.name.to_ascii_lowercase() == "all" {
		msg.to.addr = Address::empty();
		msg.to.ext_addr = None;
	}

	if msg.area == Area::Netmail {
		// correct from FROM and TO using INTL, FMPT, TOPT
		if let Some(kludges) = &msg.kludges.custom {
			for s in kludges.iter().filter(|s| s.len() > 5) {
				match &s[..5] {
					INTL => {
						let mut i = s[INTL.len()..].trim().split(' ');

						let dest = i.next().and_then(|x| Address::from_str(x).ok());
						let orig = i.next().and_then(|x| Address::from_str(x).ok());

						match (dest, orig) {
							(Some(dest), Some(orig)) => {
								msg.to.addr.zone = dest.zone;
								msg.to.addr.net = dest.net;
								msg.to.addr.node = dest.node;

								msg.from.addr.zone = orig.zone;
								msg.from.addr.net = orig.net;
								msg.from.addr.node = orig.node;
							}
							_ => {
								eprintln!("INTL parse fail: {}", s);
							}
						}
					}
					FMPT => {
						if let Ok(val) = u16::from_str(s[FMPT.len()..].trim()) {
							msg.from.addr.point = val;
						} else {
							eprintln!("FMPT parse fail: {}", s);
						}
					}
					TOPT => {
						if let Ok(val) = u16::from_str(s[TOPT.len()..].trim()) {
							msg.to.addr.point = val;
						} else {
							eprintln!("TOPT parse fail: {}", s);
						}
					}
					_ => {}
				}
			}
		}
	}

	Ok(())
}

#[derive(Eq, PartialEq, Debug)]
enum AddressKind {
	Native(Address),
	External(String),
}

#[derive(Eq, PartialEq, Debug)]
struct MessageId {
	addr: AddressKind,
	serial: u32,
}

impl MessageId {
	fn nat(addr: Address, serial: u32) -> Self {
		Self {
			addr: AddressKind::Native(addr),
			serial,
		}
	}

	fn ext(addr: String, serial: u32) -> Self {
		Self {
			addr: AddressKind::External(addr),
			serial,
		}
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseMessageIdError {
	InvalidFormat,
}

impl std::fmt::Display for ParseMessageIdError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidFormat => "Format is not valid. It should be `origaddr serialno`.",
		}
		.fmt(f)
	}
}

impl std::str::FromStr for MessageId {
	type Err = ParseMessageIdError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut i = s.rsplit(' ');

		match (i.next(), i.next()) {
			(Some(ser), Some(addr)) => {
				if ser.len() > 8 {
					return Err(Self::Err::InvalidFormat);
				}

				let sl = u32::from_str_radix(ser, 16).map_err(|_| Self::Err::InvalidFormat)?;

				Ok(if let Ok(a) = Address::from_str(addr) {
					MessageId::nat(a, sl)
				} else {
					MessageId::ext(addr.to_string(), sl)
				})
			}
			_ => Err(Self::Err::InvalidFormat),
		}
	}
}

pub type NetNodePair = (u16, u16);

#[derive(Debug, PartialEq, Eq)]
pub enum NetNodePairError {
	InvalidFormat,
	Overflow,
}

impl std::fmt::Display for NetNodePairError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidFormat => {
				"Format is not valid. It should be either a `node` or a pair `net/node` separated by a space."
			}
			Self::Overflow => "Number is too large to fit in target type.",
		}
		.fmt(f)
	}
}

fn parse_net_node_pairs(s: &str) -> Result<Vec<NetNodePair>, NetNodePairError> {
	let map_parse_int_err = |err: ParseIntError| match err.kind() {
		IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => NetNodePairError::Overflow,
		_ => NetNodePairError::InvalidFormat,
	};

	let mut pairs = Vec::new();

	for p in s.split(' ') {
		let mut i = p.split('/');

		match (i.next(), i.next()) {
			(Some(net), Some(node)) => {
				let net: u16 = net.parse().map_err(map_parse_int_err)?;
				let node: u16 = node.parse().map_err(map_parse_int_err)?;

				pairs.push((net, node));
			}
			(Some(node), None) if !pairs.is_empty() => {
				let node: u16 = node.parse().map_err(map_parse_int_err)?;

				pairs.push((pairs.last().map_or(0, |x| x.0), node));
			}
			_ => {
				return Err(NetNodePairError::InvalidFormat);
			}
		}
	}

	Ok(pairs)
}

fn parse_replyto(s: &str) -> Result<(Address, &str), ParseAddressError> {
	let mut i = s.rsplit(' ');

	match (i.next(), i.next()) {
		(Some(name), Some(addr)) => Ok((Address::from_str(addr)?, name)),
		(Some(addr), None) => Ok((Address::from_str(addr)?, "")),
		_ => Err(ParseAddressError::InvalidFormat),
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum DateTimeError {
	Format,
	Date { year: u32, month: u32, day: u32 },
	Time { hour: u32, minute: u32, second: u32 },
}

impl DateTimeError {
	fn date(year: u32, month: u32, day: u32) -> Self {
		DateTimeError::Date { year, month, day }
	}

	fn time(hour: u32, minute: u32, second: u32) -> Self {
		DateTimeError::Time { hour, minute, second }
	}
}

const FTN_MONTHS: &[&str] = &[
	"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn parse_ftn_datetime(s: &str) -> Result<NaiveDateTime, DateTimeError> {
	if s.len() != 19 {
		return Err(DateTimeError::Format);
	}

	let map_parse_int_err = |_| DateTimeError::Format;

	match (
		&s[..2],
		&s[2..3],
		&s[3..6],
		&s[6..7],
		&s[7..9],
		&s[9..11],
		&s[11..13],
		&s[13..14],
		&s[14..16],
		&s[16..17],
		&s[17..],
	) {
		(day, " ", month, " ", year, "  ", hh, ":", mm, ":", ss) => {
			let (day, month, mut year) = (
				day.trim().parse().map_err(map_parse_int_err)?,
				FTN_MONTHS
					.iter()
					.position(|&x| x == month)
					.ok_or(DateTimeError::Format)? as u32
					+ 1,
				year.parse::<u32>().map_err(map_parse_int_err)?,
			);

			year += if year >= 90 { 1900 } else { 2000 };

			let (hh, mm, ss) = (
				hh.parse().map_err(map_parse_int_err)?,
				mm.parse().map_err(map_parse_int_err)?,
				ss.parse().map_err(map_parse_int_err)?,
			);

			Ok(NaiveDate::from_ymd_opt(year as i32, month, day)
				.ok_or_else(|| DateTimeError::date(year, month, day))?
				.and_hms_opt(hh, mm, ss)
				.ok_or_else(|| DateTimeError::time(hh, mm, ss))?)
		}
		_ => Err(DateTimeError::Format),
	}
}

#[cfg(test)]
mod test {
	use super::{
		parse_ftn_datetime, parse_net_node_pairs, parse_replyto, Address, DateTimeError, MessageId, NetNodePairError,
		ParseAddressError, ParseMessageIdError,
	};
	use std::str::FromStr;

	#[test]
	fn parse_valid_address() {
		assert_eq!(Address::from_str("2:50/0"), Ok(Address::new_4d(2, 50, 0, 0)));

		assert_eq!(Address::from_str("2:1024/255"), Ok(Address::new_4d(2, 1024, 255, 0)));
		assert_eq!(Address::from_str("2:1024/255.0"), Ok(Address::new_4d(2, 1024, 255, 0)));
		assert_eq!(
			Address::from_str("2:1024/255.768"),
			Ok(Address::new_4d(2, 1024, 255, 768))
		);

		assert_eq!(
			Address::from_str("1:1024/255@Fidonet"),
			Ok(Address::full(1, 1024, 255, 0, Some("Fidonet".to_string())))
		);
		assert_eq!(
			Address::from_str("1:1024/255.768@Fidonet"),
			Ok(Address::full(1, 1024, 255, 768, Some("Fidonet".to_string())))
		);
		assert_eq!(
			Address::from_str("1:1024/255.768@Fid@net"),
			Ok(Address::full(1, 1024, 255, 768, Some("Fid@net".to_string())))
		);

		assert_eq!(
			Address::from_str("1:1024/255@"),
			Ok(Address::full(1, 1024, 255, 0, Some("".to_string())))
		);
		assert_eq!(
			Address::from_str("1:1024/255.768@"),
			Ok(Address::full(1, 1024, 255, 768, Some("".to_string())))
		);
	}

	#[test]
	fn fail_on_invalid_address() {
		use ParseAddressError::*;

		assert_eq!(Address::from_str(":").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2:").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("123456:").unwrap_err(), Overflow);

		assert_eq!(Address::from_str("2:aaaa").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2:1024").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2:1024/").unwrap_err(), InvalidFormat);

		assert_eq!(Address::from_str("2:1024/123456").unwrap_err(), Overflow);
		assert_eq!(Address::from_str("2:1024/-100").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2:1024//100").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("2:1024/100.200.300").unwrap_err(), InvalidFormat);

		assert_eq!(Address::from_str("2:1024/c.d").unwrap_err(), InvalidFormat);
		assert_eq!(Address::from_str("a:b/c.d").unwrap_err(), InvalidFormat);
	}

	#[test]
	fn parse_valid_msgid() {
		assert_eq!(
			MessageId::from_str("2:1024/255 4a34c4dd"),
			Ok(MessageId::nat(Address::new_4d(2, 1024, 255, 0), 0x4a34c4dd))
		);
		assert_eq!(
			MessageId::from_str("2:1024/255.100@Fidonet 4a34c4dd"),
			Ok(MessageId::nat(
				Address::full(2, 1024, 255, 100, Some("Fidonet".to_string())),
				0x4a34c4dd
			))
		);

		assert_eq!(
			MessageId::from_str("<1234567890@www.fido-online.com> 4A34C4DD"),
			Ok(MessageId::ext(
				"<1234567890@www.fido-online.com>".to_string(),
				0x4a34c4dd
			))
		);
	}

	#[test]
	fn fail_on_invalid_msgid() {
		use ParseMessageIdError::*;

		assert_eq!(MessageId::from_str("2:1024/255 12345678 ").unwrap_err(), InvalidFormat);
		assert_eq!(MessageId::from_str("2:1024/255 123456789").unwrap_err(), InvalidFormat);

		// serials in some messages can be less than 8 characters
		// assert_eq!(MessageId::from_str("2:1024/255 1234567").unwrap_err(), InvalidFormat);
		assert_eq!(MessageId::from_str("2:1024/255 0x123456").unwrap_err(), InvalidFormat);
	}

	#[test]
	fn parse_valid_pairs() {
		assert_eq!(
			parse_net_node_pairs("1024/100 200 300"),
			Ok(vec![(1024, 100), (1024, 200), (1024, 300)])
		);
		assert_eq!(
			parse_net_node_pairs("1024/100 4096/200 300"),
			Ok(vec![(1024, 100), (4096, 200), (4096, 300)])
		);

		// consider zero is valid
		assert_eq!(parse_net_node_pairs("0/100 200"), Ok(vec![(0, 100), (0, 200)]));
		assert_eq!(
			parse_net_node_pairs("1024/0 0 0"),
			Ok(vec![(1024, 0), (1024, 0), (1024, 0)])
		);
	}

	#[test]
	fn fail_on_invalid_pairs() {
		use NetNodePairError::*;

		assert_eq!(parse_net_node_pairs("1024").unwrap_err(), InvalidFormat);
		assert_eq!(parse_net_node_pairs("1024/").unwrap_err(), InvalidFormat);
		assert_eq!(parse_net_node_pairs("/1024").unwrap_err(), InvalidFormat);
		assert_eq!(parse_net_node_pairs("1024/100  200").unwrap_err(), InvalidFormat);
		assert_eq!(parse_net_node_pairs("1024/100 200 ").unwrap_err(), InvalidFormat);
		assert_eq!(parse_net_node_pairs("100 4096/200 300").unwrap_err(), InvalidFormat);
	}

	#[test]
	fn parse_valid_replyto() {
		assert_eq!(parse_replyto("2:46/128"), Ok((Address::new_4d(2, 46, 128, 0), "")));
		assert_eq!(
			parse_replyto("2:5020/400 UUCP"),
			Ok((Address::new_4d(2, 5020, 400, 0), "UUCP"))
		);
		assert_eq!(
			parse_replyto("2:5020/400.100 UUCP"),
			Ok((Address::new_4d(2, 5020, 400, 100), "UUCP"))
		);
	}

	#[test]
	fn fail_on_invalid_replyto() {
		use ParseAddressError::*;

		assert_eq!(parse_replyto("2:46 UUCP").unwrap_err(), InvalidFormat);
	}

	#[test]
	fn parse_valid_ftn_datetime() {
		use chrono::NaiveDate;

		assert_eq!(
			parse_ftn_datetime("12 Dec 93  14:42:12"),
			Ok(NaiveDate::from_ymd(1993, 12, 12).and_hms(14, 42, 12))
		);
		assert_eq!(
			parse_ftn_datetime(" 3 Oct 07  23:00:29"),
			Ok(NaiveDate::from_ymd(2007, 10, 03).and_hms(23, 00, 29))
		);
		assert_eq!(
			parse_ftn_datetime("31 Oct 09  23:01:04"),
			Ok(NaiveDate::from_ymd(2009, 10, 31).and_hms(23, 01, 04))
		);
		assert_eq!(
			parse_ftn_datetime("01 Mar 20  01:43:10"),
			Ok(NaiveDate::from_ymd(2020, 03, 01).and_hms(01, 43, 10))
		);
	}

	#[test]
	fn fail_on_invalid_ftn_datetime() {
		use DateTimeError::*;

		assert_eq!(parse_ftn_datetime("12 Dec 93 14:42:12").unwrap_err(), Format);
		assert_eq!(parse_ftn_datetime("12 Dec 93  14;42;12").unwrap_err(), Format);
	}
}
