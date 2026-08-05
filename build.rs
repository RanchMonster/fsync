fn main() {
   let app_version = std::env::var("CARGO_PKG_VERSION").unwrap();
   let protocol_version = app_version.chars().next().unwrap(); // the first character of the version is the protocol version
   println!("cargo:rustc-env=PROTOCOL_VERSION={}", protocol_version);
}
