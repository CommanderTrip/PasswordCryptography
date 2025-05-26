mod db;
mod crypto;

#[macro_use] extern crate rocket;
use rocket::response::status;
use serde::Deserialize;
use rocket::serde::json::Json;
use crate::crypto::CryptoType;
use crate::db::{add_user};

#[derive(Deserialize, Debug)]
struct UserRegister {
    username: String,
    password: String,
    crypto_type: CryptoType
}

#[get("/")]
fn index() -> &'static str {
    "
    /register with {username, password, crypto_type}\n
    crypto_types include: Plain, Hashed, HashedAndSalted
    "
}

#[post("/register", format="application/json", data="<user_register>")]
fn register(user_register: Option<Json<UserRegister>>) -> Result<status::Accepted<String>, status::BadRequest<String>> {

    let username;
    let password;

    // Field Validation
    match &user_register {
        Some(user) => {
            if user.username.is_empty() || user.password.is_empty() {
                return Err(status::BadRequest(String::from("Empty Fields")));
            }

            username = user.username.clone();

            match user.crypto_type {
                CryptoType::Plain => password = crypto::plain_password(user.password.clone()),
                CryptoType::Hashed => password = crypto::hash_password(user.password.clone()),
                CryptoType::HashedAndSalted => password = crypto::hash_and_salt_password(user.password.clone()),
                CryptoType::Argon2 => password = crypto::argon2_password(user.password.clone())
            }
        },
        None =>  {
            return Err(status::BadRequest(String::from("Invalid Fields")));
        }
    }

    match add_user(username, password) {
        Ok(_) => {
            Ok(status::Accepted(String::from("User Registered")))
        },
        Err(_) => {
            Err(status::BadRequest(String::from("Error with DB")))
        }
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index, register])
}