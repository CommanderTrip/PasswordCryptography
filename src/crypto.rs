use std::fmt;
use rocket::serde::Deserialize;
use sha2::{Sha256, Digest};
use rand::prelude::*;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString
    },
    Argon2
};
use crate::crypto::CryptoType::Argon2 as A2;

#[derive(Deserialize, Debug)]
pub enum CryptoType {
    Plain,
    Hashed,
    HashedAndSalted,
    Argon2,
}

impl fmt::Display for CryptoType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoType::Plain => {write!(f, "Plain")}
            CryptoType::Hashed => {write!(f, "Hashed")}
            CryptoType::HashedAndSalted => {write!(f, "HashedAndSalted")},
            CryptoType::Argon2 => {write!(f, "Argon2")}
        }
    }
}

pub struct Password {
    pub password: String,
    pub salt: String,
    pub crypto_type: CryptoType
}

/// Worst thing to do. NEVER DO THIS
pub fn plain_password(password: String) -> Password {
    Password {
        password,
        salt: String::from(""),
        crypto_type: CryptoType::Plain
    }
}

/// Better but still some flaws.
/// 1. Users with the same password collide on the same hash
/// 2. Hashes are weak to Rainbow table attacks
pub fn hash_password(password: String) -> Password {
    let password_bytes = password.as_bytes();
    let hashed_pass = Sha256::digest(password_bytes);
    
    Password {
        password: hex::encode(hashed_pass),
        salt: String::from(""),
        crypto_type: CryptoType::Hashed
    }
}

/// Pretty good now, but if the attacker knows how we combine the salt and password/use a simple
/// combination like here then it would be easy to eventually brute force offline
pub fn hash_and_salt_password(password: String) -> Password {
    // Don't add salt and password as strings. Use them at the byte level.
    let mut salt_bytes = [0u8; 16]; // 16 bytes is the minimum recommended length
    OsRng.fill_bytes(&mut salt_bytes);
    let password_bytes = password.as_bytes();

    // Join the salt and password (salt + password)
    let mut salt_pass_bytes: Vec<u8> = vec![];
    for byte in salt_bytes.iter() {
        salt_pass_bytes.push(*byte);
    }
    for byte in password_bytes.iter() {
        salt_pass_bytes.push(*byte);
    }
    salt_pass_bytes.as_slice();

    let hashed_pass = Sha256::digest(salt_pass_bytes);
    
    Password {
        password: hex::encode(hashed_pass),
        salt: hex::encode(salt_bytes),
        crypto_type: CryptoType::HashedAndSalted
    }
}

pub fn argon2_password(password: String) -> Password {
    let password_bytes = password.as_bytes();
    
    let argon2 = Argon2::default();
    
    let hashed_pass =  match argon2.hash_password(password_bytes, &SaltString::generate(&mut OsRng)) {
        Ok(pass)  => {
            pass.to_string()
        },
        Err(_) => panic!("Failed to Hash Password"),
    };
    
    Password {
        password: hashed_pass,
        salt: String::from(""),
        crypto_type: A2
    }
}