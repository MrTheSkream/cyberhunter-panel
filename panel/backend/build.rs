// Changer la clé publique de mise à jour doit recompiler le binaire (voir services/update_source.rs).
fn main() {
    println!("cargo:rerun-if-env-changed=CYBERHUNTER_UPDATE_PUBKEY");
}
