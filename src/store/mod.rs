use rusqlite::{named_params, Connection, Error, Result, Transaction};
use std::{cell::RefCell, fmt::Write, path::Path};

use crate::core::{Message, NetNodePair};

#[macro_use]
mod sql_macro;

pub struct MessageBase {
	conn: RefCell<Connection>,
}

impl MessageBase {
	pub fn open(path: &Path) -> Result<Self> {
		// let conn = if path.is_file() {
		// 	Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?
		// } else {
		// 	prepare_database(Connection::open(path)?)?
		// };

		let conn = prepare_database(Connection::open(path)?)?;
		conn.pragma_update(None, "foreign_keys", "ON")?;
		conn.pragma_update(None, "temp_store", "MEMORY")?;
		conn.pragma_update(None, "journal_mode", "WAL")?;
		conn.pragma_update(None, "synchronous", "NORMAL")?;

		Ok(Self {
			conn: RefCell::new(conn),
		})
	}

	pub fn toss(&self, msg: Message) -> Result<i64> {
		let mut conn = self.conn.borrow_mut();
		let tran = conn.transaction()?;

		if let Ok(id) = tran.query_row(
			"
			select
				id
			from
				messages
			where
				msgid_serial = :serial
				and posted = replace(:posted, 'T', ' ')
			",
			named_params! {
				":serial": msg.msgid_serial,
				":posted": msg.posted,
			},
			|r| r.get::<_, i64>(0),
		) {
			eprintln!(
				"Message ({}, {:08x}) skipped because of a duplicate #{}",
				msg.posted, msg.msgid_serial, id
			);

			return Ok(-1); // TODO: report that dupe has been skipped
		}

		let subj = get_subj_id(&tran, &msg.subj)?;
		let from = get_user_id(&tran, &msg.from)?;

		let to = {
			let id = if let Some(id) = msg.reply_serial {
				match tran.query_row(
					r#"
					select
						m.from_id
					from
						messages m,
						users u
					where
						m.from_id = u.id
						and m.msgid_serial = :reply
						and u.name = trim(:name)
					"#,
					named_params! {
						":reply": id,
						":name": msg.to.name,
					},
					|r| r.get::<_, i64>(0),
				) {
					Err(Error::QueryReturnedNoRows) => Ok(0),
					Ok(v) => Ok(v),
					Err(e) => Err(e),
				}
			} else {
				Ok(0)
			}?;

			if id > 0 {
				id
			} else {
				get_user_id(&tran, &msg.to)?
			}
		};

		let seen_by = get_seenby_id(&tran, &msg.kludges.seen_by)?;
		let path = get_path_id(&tran, &msg.kludges.path)?;
		let pid = msg.kludges.pid.map_or(Ok(0), |x| get_software_id(&tran, &x))?;
		let tid = msg.kludges.tid.map_or(Ok(0), |x| get_software_id(&tran, &x))?;
		let tear_line = get_tear_line_id(&tran, &msg.tear_line)?;
		let origin = get_origin_id(&tran, &msg.origin)?;

		tran.execute(
			r#"
			insert into messages (
				posted,
				tzutc,
				msgid_serial,
				reply_serial,
				msgid_address,
				reply_address,
				from_id,
				to_id,
				flags,
				subject_id,
				body,
				tear_line_id,
				origin_id,
				pid_id,
				tid_id,
				seen_by_id,
				path_id
			) values (
				replace(:posted, 'T', ' '),
				nullif(trim(:tzutc), ''),
				:msgid_serial,
				nullif(:reply_serial, 0),
				nullif(trim(:msgid_addr), ''),
				nullif(trim(:reply_addr), ''),
				:from,
				:to,
				:flags,
				nullif(:subj, 0),
				:body,
				nullif(:tear_line, 0),
				nullif(:origin, 0),
				nullif(:pid, 0),
				nullif(:tid, 0),
				nullif(:seen_by, 0),
				nullif(:path, 0)
			)"#,
			named_params! {
				":posted": msg.posted,
				":tzutc": msg.kludges.tzutc,
				":msgid_serial": msg.msgid_serial,
				":reply_serial": msg.reply_serial,
				":msgid_addr": msg.msgid_addr,
				":reply_addr": msg.reply_addr,
				":from": from,
				":to": to,
				":flags": msg.flags,
				":subj": subj,
				":body": msg.body,
				":tear_line": tear_line,
				":origin": origin,
				":pid": pid,
				":tid": tid,
				":seen_by": seen_by,
				":path": path,
			},
		)?;

		let id = tran.last_insert_rowid();

		if let Some(ref kludges) = msg.kludges.custom {
			for kl in kludges {
				tran.execute(
					"insert into kludges (message_id, kludge) values (:id, :kludge)",
					named_params! {
						":id": id,
						":kludge": kl,
					},
				)?;
			}
		}

		tran.commit()?;

		Ok(id)
	}
}

fn get_user_id(tran: &Transaction, user: &crate::core::User) -> Result<i64> {
	select_or_insert!(
		tran,
		r#"
		select
			id
		from
			users
		where
			coalesce(name, '') = coalesce(nullif(trim(:name), ''), '<empty>')
			and coalesce(zone, 0) = :zone
			and coalesce(net, 0) = :net
			and coalesce(node, 0) = :node
			and coalesce(point, 0) = :point
			and coalesce(domain, '') = trim(:domain)
			and coalesce(foreign_address, '') = trim(:ext_addr)
		"#,
		r#"
		insert into users (
			name,
			zone,
			net,
			node,
			point,
			domain,
			foreign_address
		) values (
			coalesce(nullif(trim(:name), ''), '<empty>'),
			nullif(:zone, 0),
			nullif(:net, 0),
			nullif(:node, 0),
			nullif(:point, 0),
			nullif(trim(:domain), ''),
			nullif(trim(:ext_addr), '')
		)"#,
		named_params! {
			":name": user.name,
			":zone": user.addr.zone,
			":net": user.addr.net,
			":node": user.addr.node,
			":point": user.addr.point,
			":domain": user.addr.domain,
			":ext_addr": user.ext_addr,
		}
	)
}

fn get_software_id(tran: &Transaction, name: &str) -> Result<i64> {
	if name.trim().is_empty() {
		return Ok(0);
	}

	select_or_insert!(
		tran,
		"select id from software where name = trim(:name)",
		"insert into software (name) values (trim(:name))",
		named_params! { ":name": name }
	)
}

fn get_subj_id(tran: &Transaction, subj: &str) -> Result<i64> {
	if subj.trim().is_empty() {
		return Ok(0);
	}

	select_or_insert!(
		tran,
		"select id from subjects where subject = trim(:subj)",
		"insert into subjects (subject) values (trim(:subj))",
		named_params! { ":subj": subj }
	)
}

fn get_tear_line_id(tran: &Transaction, tl: &str) -> Result<i64> {
	if tl.trim().is_empty() {
		return Ok(0);
	}

	select_or_insert!(
		tran,
		"select id from tear_lines where tear_line = trim(:tl)",
		"insert into tear_lines (tear_line) values (trim(:tl))",
		named_params! { ":tl": tl }
	)
}

fn get_origin_id(tran: &Transaction, origin: &str) -> Result<i64> {
	if origin.trim().is_empty() {
		return Ok(0);
	}

	select_or_insert!(
		tran,
		"select id from origins where origin = trim(:origin)",
		"insert into origins (origin) values (trim(:origin))",
		named_params! { ":origin": origin }
	)
}

fn get_seenby_id(tran: &Transaction, seen_by: &Option<Vec<NetNodePair>>) -> Result<i64> {
	let seen_by = if let Some(val) = seen_by.as_ref().filter(|x| !x.is_empty()) {
		val
	} else {
		return Ok(0);
	};

	// make an array of arrays
	let mut arr = String::new();
	arr.push('[');

	let mut i = seen_by.iter().peekable();

	while let Some((net, node)) = i.next() {
		write!(arr, "[{},{}]", net, node).unwrap();

		if i.peek().is_some() {
			arr.push(',');
		}
	}

	arr.push(']');

	// NB: values should be sorted by "net", "node" in order to compare resulting json array
	select_or_insert_v2!(
		tran,
		r#"
		select
			v.id
		from (
			select
				s.id,
				json_group_array(json_array(s.net, s.node)) as arr
			from (
				select id, net, node from seen_bys order by id, net, node
			) s
			group by
				s.id
		) v
		where
			v.arr = (
				select
					json_group_array(json_array(net, node))
				from (
					select
						json_extract(v.value, '$[0]') as net,
						json_extract(v.value, '$[1]') as node
					from
						json_each(json(:arr)) v
					order by
						net,
						node
				) a
			)
		"#,
		r#"
		insert into seen_bys (
			id,
			net,
			node
		)
		select
			v.id,
			v.net,
			v.node
		from (
			select
				(select coalesce(max(s.id), 0) + 1 from seen_bys s) as id,
				json_extract(v.value, '$[0]') as net,
				json_extract(v.value, '$[1]') as node
			from
				json_each(:arr) v
		) v
		order by
			v.net,
			v.node
		"#,
		"select max(id) from seen_bys",
		named_params! { ":arr": arr }
	)
}

fn get_path_id(tran: &Transaction, path: &Option<Vec<NetNodePair>>) -> Result<i64> {
	let path = if let Some(val) = path.as_ref().filter(|x| !x.is_empty()) {
		val
	} else {
		return Ok(0);
	};

	// make an array of arrays
	let mut arr = String::new();
	arr.push('[');

	let mut i = path.iter().peekable();

	while let Some((net, node)) = i.next() {
		write!(arr, "[{},{}]", net, node).unwrap();

		if i.peek().is_some() {
			arr.push(',');
		}
	}

	arr.push(']');

	select_or_insert_v2!(
		tran,
		r#"
		select
			v.id
		from (
			select
				p.id,
				json_group_array(json_array(p.net, p.node)) as arr
			from (
				select id, net, node from paths order by id, position
			) p
			group by
				p.id
		) v
		where
			v.arr = json(:arr)
		"#,
		r#"
		insert into paths (
			id,
			position,
			net,
			node
		)
		select
			v.id,
			row_number() over () as pos,
			v.net,
			v.node
		from (
			select
				(select coalesce(max(p.id), 0) + 1 from paths p) as id,
				json_extract(v.value, '$[0]') as net,
				json_extract(v.value, '$[1]') as node
			from
				json_each(:arr) v
		) v
		"#,
		"select max(id) from paths",
		named_params! { ":arr": arr }
	)
}

fn prepare_database(conn: Connection) -> Result<Connection> {
	conn.execute_batch(
		r#"
PRAGMA page_size = 8192;

begin;

-- users
create table if not exists users (
	id                  integer primary key autoincrement,
	name                text not null,
	zone                integer,
	net                 integer,
	node                integer,
	point               integer,
	domain              text,
	foreign_address     text
);

-- subjects
create table if not exists subjects (
	id              integer primary key autoincrement,
	subject         text not null
);

-- seen_bys
create table if not exists seen_bys (
	id              integer not null,
	net             integer not null,
	node            integer not null
);

create index if not exists seen_by_index on seen_bys (id, net, node);

-- paths
create table if not exists paths (
	id              integer not null,
	position        integer not null,
	net             integer not null,
	node            integer not null
);

create unique index if not exists path_index on paths (id, position);

-- software (PIDs and TIDs)
create table if not exists software (
	id              integer primary key autoincrement,
	name            text not null
);

-- tear_lines
create table if not exists tear_lines (
	id              integer primary key autoincrement,
	tear_line       text not null
);

-- origins
create table if not exists origins (
	id              integer primary key autoincrement,
	origin          text not null
);

-- messages
create table if not exists messages (
	id              integer primary key autoincrement,
	posted          text not null,
	tzutc           text,
	tossed          text default (current_timestamp),
	msgid_serial    integer not null,
	reply_serial    integer,
	msgid_address   text,
	reply_address   text,
	from_id         integer not null references users (id),
	to_id           integer not null references users (id),
	flags           integer not null,
	subject_id      integer references subjects (id),
	body            text,
	tear_line_id    integer references tear_lines (id),
	origin_id       integer references origins (id),
	pid_id          integer references software (id),
	tid_id          integer references software (id),
	seen_by_id      integer,
	path_id         integer
);

create unique index if not exists no_dupes on messages (msgid_serial, posted);
create index if not exists reply_serial_index on messages (reply_serial);
create index if not exists subject_id_index on messages (subject_id);
create index if not exists posted_index on messages (posted);

-- kludges
create table if not exists kludges (
	message_id      integer not null references messages (id),
	kludge          text not null
);

create index if not exists kludge_index on kludges (message_id);

commit;
	"#,
	)?;

	Ok(conn)
}
