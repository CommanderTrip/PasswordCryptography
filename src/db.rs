use rusqlite::{params, Connection, Result};
use crate::crypto::Password;

pub fn add_user(username: String, password: Password) -> Result<()> {
    let connection = Connection::open("./users.db")?;
    
    connection.execute("
        CREATE TABLE if not exists users (
            username text,
            password text,
            salt text,
            crypto_type text
        )",
        [],
    )?;

    connection.execute(
        "INSERT INTO users (username, password, salt, crypto_type) values (?1, ?2, ?3, ?4)",
        params![username, password.password, password.salt, password.crypto_type.to_string()]
    )?;

    Ok(())
}