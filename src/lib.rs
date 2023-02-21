/*!
unofficial [keyauth](https://keyauth.cc) library that implements all versions of the api.
to make an api version available use the feature flag for that version.
example
```toml
keyauth = { version = "*", features = ["seller"] } # this will enable 1.2 (default) and seller api
```
by default the 1.2 api is enabled because it is most commonly used. so if you dont want the 1.2 api you have to disable it.
```toml
keyauth = { version = "*", features = ["1.1", "seller"], default-features = false } # this will enable 1.1 and seller api
```

basic usage:
```rust
let mut auth = keyauth::v1_2::KeyauthApi::new("application name", "ownerid", "application secret", "application version", "api url"); // if you dont have a custom domain for api use "https://keyauth.win/api/1.2/"
auth.init().unwrap();
auth.login("username", "password", Some("hwid".to_string()).unwrap(); // if you want to automaticly generate hwid use None insted.
```

also if you want to use an obfuscator for rust i recommend using [obfstr](https://crates.io/crates/obfstr) and [llvm obfuscator](https://github.com/eshard/obfuscator-llvm/wiki/Rust-obfuscation-guide)
*/

#[cfg(feature = "v1_0")]
pub mod v1_0;
#[cfg(feature = "v1_1")]
pub mod v1_1;
#[cfg(feature = "v1_2")]
pub mod v1_2;
#[cfg(feature = "seller")]
pub mod seller;

#[cfg(test)]
mod test;