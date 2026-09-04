fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let include = protoc_bin_vendored::include_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_prost_build::configure().compile_protos(
        &["../../proto/authguard/access/v1/access_context.proto"],
        &["../../proto", include.to_str().ok_or("invalid protoc include path")?],
    )?;
    println!("cargo:rerun-if-changed=../../proto/authguard/access/v1/access_context.proto");
    Ok(())
}
