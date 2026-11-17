fn main() {
    // C++ native helpers (Win32 memory/priority/elevation APIs)
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        cc::Build::new()
            .cpp(true)
            .file("native/oph_native.cpp")
            .flag_if_supported("/std:c++17")
            .flag_if_supported("/EHsc")
            .compile("oph_native");
        println!("cargo:rustc-link-lib=psapi");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rerun-if-changed=native/oph_native.cpp");
    }
    // embed our manifest (administrator + common controls + per-monitor DPI)
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")));
    println!("cargo:rerun-if-changed=app.manifest");
    tauri_build::try_build(attrs).expect("tauri build")
}
