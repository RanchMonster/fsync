fn main() {
   let app_version = std::env::var("CARGO_PKG_VERSION").unwrap();
   let protocol_version = app_version.split('.').next().unwrap_or("0");
   println!("cargo:rustc-env=PROTOCOL_VERSION={}", protocol_version);
}
