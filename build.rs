//! Rebuild embedded `SQLx` migrations when the migration directory changes.

fn main() {
    // SQLx embeds the migration directory; newly added files must rebuild it too.
    println!("cargo:rerun-if-changed=migrations");
}
