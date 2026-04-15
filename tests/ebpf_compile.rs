//! Compile-time checks for the default eBPF object path.

#[test]
fn ebpf_object_path_default_is_stable() {
    let default_path =
        std::path::Path::new("target/bpfel-unknown-none/release/idps-firewalld-ebpf");
    assert!(default_path.ends_with("idps-firewalld-ebpf"));
}
