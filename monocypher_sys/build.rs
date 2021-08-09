extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    // Compile monocypher from the source in the submodule.
    cc::Build::new()
        .file("Monocypher/src/monocypher.c")
        .include("Monocypher/src")
        .compile("monocypher");


    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("Monocypher/src/monocypher.h")
        .blacklist_type("max_align_t")
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
