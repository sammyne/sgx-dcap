use sgx_types::*;

pub fn error_out_if_not_ok(status: sgx_status_t, tip: &str) -> Result<(), String> {
    if status == sgx_status_t::SGX_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, status))
}

pub fn qe3_error_out_if_not_ok(err: sgx_quote3_error_t, tip: &str) -> Result<(), String> {
    if err == sgx_quote3_error_t::SGX_QL_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, err))
}
