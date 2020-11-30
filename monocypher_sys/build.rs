fn main() {
    // Tell cargo to tell rustc to link the monocypher
    // shared library.
    println!("cargo:rustc-link-lib=monocypher");

    cc::Build::new()
        .file("src/monocypher.c")
        .flag("-O3")
        .compile("monocypher");
}
