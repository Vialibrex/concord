fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=c++abi");
        println!("cargo:rustc-cdylib-link-arg=-Wl,-z,defs");
        println!("cargo:rustc-cdylib-link-arg=-Wl,--pack-dyn-relocs=android");
        // No `--icf`: lld 19-23 folds outliner stubs holding the ADRPs of two folded functions'
        // GOT slots but keeps both slots, so a caller adds its slot's offset to the other's page.
    }
}
