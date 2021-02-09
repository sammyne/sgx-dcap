fn main() {
    // order is important, DCAP related libraries must come before those of SGX
    // these libraries reside in /usr/lib/x86_64-linux-gnu/
    // before SGX SDK v2.8, sgx_dcap_quote_verify is named as dcap_quote_verify
    println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");
    println!("cargo:rustc-link-lib=dylib=sgx_default_qcnl_wrapper");
    println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
}
