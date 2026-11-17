// The update signing key is a COMPILE-TIME input (`option_env!` in
// `services/release_verify.rs`). Without this line cargo would not rebuild
// when only the environment variable changes, and a binary could silently
// keep the previous key, or none.
fn main() {
    println!("cargo:rerun-if-env-changed=CYBERHUNTER_UPDATE_PUBKEY");
}
