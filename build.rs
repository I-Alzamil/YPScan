fn main() -> Result<(),Box<dyn std::error::Error>> {
    #[cfg(all(feature = "yara_c", feature = "yara_x"))]
    compile_error!("feature \"yara_c\" and feature \"yara_x\" cannot be enabled at the same time. Use \"--no-default-features\" to disable yara_c");

    built::write_built_file().expect("Failed to acquire build-time information");

    platform_specific_arguments()?;
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn platform_specific_arguments() -> Result<(),Box<dyn std::error::Error>> {
    use winresource::WindowsResource;

    #[cfg(feature = "yara_c")]
    println!("cargo:rustc-link-lib=user32");

    #[cfg(feature = "yara_c")]
    let file_description = "YPScan";

    #[cfg(feature = "yara_x")]
    let file_description = "YPScanX";
    
    WindowsResource::new()
        // This path can be absolute, or relative to your crate root.
        .set_icon("assets/icon.ico")
        .set("FileDescription", file_description)
        .compile()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn platform_specific_arguments() -> Result<(),Box<dyn std::error::Error>> {
    Ok(())
}