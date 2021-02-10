use sgx_types::*;

use std::{mem, ptr};

#[no_mangle]
pub unsafe extern "C" fn ocall_sgx_qe_get_quote(
    p_report: *const sgx_report_t,
    p_quote: *mut u8,
    _: u32,
    quote_size: *mut u32,
) -> sgx_quote3_error_t {
    let err = sgx_qe_get_quote_size(quote_size);
    if err != sgx_quote3_error_t::SGX_QL_SUCCESS {
        println!("[-] sgx_qe_get_quote_size => {:?}", err);
        return err;
    }
    println!("[+] sgx_qe_get_quote_size ok: quote_size={}", *quote_size);

    let err = sgx_qe_get_quote(p_report, *quote_size, p_quote);
    if err != sgx_quote3_error_t::SGX_QL_SUCCESS {
        println!("[-] sgx_qe_get_quote => {:?}", err);
        return err;
    }
    println!("[+] sgx_qe_get_quote => success");

    sgx_quote3_error_t::SGX_QL_SUCCESS
}

// ###############################################
// ######## ocall_sgx_qe_get_target_info #########
// ###############################################
#[no_mangle]
pub extern "C" fn ocall_sgx_qe_get_target_info(
    qe_target: *mut sgx_target_info_t,
) -> sgx_quote3_error_t {
    unsafe { sgx_qe_get_target_info(qe_target) }
}

#[no_mangle]
pub unsafe extern "C" fn ocall_sgx_qv_verify_quote(
    quote: *const u8,
    quote_size: u32,
    expiration_check_date: time_t,
    collateral_expiration_status: *mut u32,
    quote_verification_result: *mut sgx_ql_qv_result_t,
    qve_report_info: *mut sgx_ql_qe_report_info_t,
    supplemental_data: *mut sgx_ql_qv_supplemental_t,
    supplemental_data_ok: *mut u8,
) -> sgx_quote3_error_t {
    // call DCAP quote verify library to get supplemental data size
    *supplemental_data_ok = {
        let mut supplemental_data_size = 0u32;
        let qve_err = qv::sgx_qv_get_quote_supplemental_data_size(&mut supplemental_data_size);
        if qve_err == sgx_quote3_error_t::SGX_QL_SUCCESS
            && supplemental_data_size == (mem::size_of::<sgx_ql_qv_supplemental_t>() as u32)
        {
            println!("[enclave+] sgx_qv_get_quote_supplemental_data_size ok");
            1
        } else {
            println!(
                "[enclave-] sgx_qv_get_quote_supplemental_data_size failed: err={:?}, ",
                qve_err
            );
            *supplemental_data_ok = 0;
            return qve_err;
        }
    };

    qv::verify_quote(
        quote,
        quote_size,
        ptr::null(),
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        qve_report_info,
        mem::size_of::<sgx_ql_qv_supplemental_t>() as u32,
        supplemental_data as *mut _ as *mut u8,
    )
}
