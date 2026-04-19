fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure().build_server(true).compile_protos(
        &["../../proto/agent/v1/agent_service.proto"],
        &["../../proto"],
    )?;

    println!("cargo:rerun-if-changed=../../proto/agent/v1/agent_service.proto");
    Ok(())
}
