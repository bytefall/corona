macro_rules! select_or_insert {
    ($conn:expr, $sel:expr, $ins:expr, $par:expr) => {{
        match $conn.query_row($sel, $par, |r| r.get(0)) {
            Err(Error::QueryReturnedNoRows) => {
                $conn.execute($ins, $par)?;

                Ok($conn.last_insert_rowid())
            }
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }};
}

macro_rules! select_or_insert_v2 {
    ($conn:expr, $sel:expr, $ins:expr, $get:expr, $par:expr) => {{
        match $conn.query_row($sel, $par, |r| r.get(0)) {
            Err(Error::QueryReturnedNoRows) => {
                $conn.execute($ins, $par)?;

                Ok($conn.query_row($get, [], |r| r.get(0))?)
            }
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }};
}
