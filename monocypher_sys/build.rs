extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Compile monocypher from the source in the submodule.
    let mut cc = cc::Build::new();
    cc.file("Monocypher/src/monocypher.c");
    cc.include("Monocypher/src");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut bindings_builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("Monocypher/src/monocypher.h")
        .blocklist_type("max_align_t");

    // Compile ed25519 and add its bindings if that feature is required.
    if cfg!(feature = "ed25519") {
        cc.file("Monocypher/src/optional/monocypher-ed25519.c");
        bindings_builder = bindings_builder
            .clang_arg("-IMonocypher/src")
            .header("Monocypher/src/optional/monocypher-ed25519.h");
    }

    cc.compile("monocypher");

    let bindings = bindings_builder
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
