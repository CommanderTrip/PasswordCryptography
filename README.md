# PasswordCryptography

Saw [this interesting video](https://www.youtube.com/watch?v=AM7cTDfg3m0) and decided to try and implement the cryptography patterns for passwords. Meant to be a fun toy project on basic password encryption. Also was good practice for web API server and SQLite. Extending functionality beyond the video to include user input "login" functionality.

Establishes an HTTP API endpoint on `localhost:8000` using [Rocket](https://crates.io/crates/rocket) and uses a local SQLite DB. Gives some instructions on `GET "/"` but the available endpoints are:

- `POST "/register"` Registers a user in the database with no uniqueness and basic validation. Must include a JSON body payload. See usage for example.
- TODO: `POST "/login"` Validates user login with provided username and password against a user in the database. 

## Usage 

```
"/register" expected body
{
    "username": "some username", 
    "password", "some plain password"
    "cryto_type" "some crypto option"
}
```

Crypto types include:

- Plain
- Hashed
- HashedAndSalted
- Argon2



