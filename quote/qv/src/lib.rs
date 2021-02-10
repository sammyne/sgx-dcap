use std::{ptr, slice};

use sgx_types::*;

pub use sgx_types::sgx_qv_get_quote_supplemental_data_size;

mod qve;

pub fn verify_quote(
    quote: *const uint8_t,
    quote_size: uint32_t,
    quote_collateral: *const sgx_ql_qve_collateral_t,
    expiration_check_date: time_t,
    collateral_expiration_status: *mut uint32_t,
    quote_verification_result: *mut sgx_ql_qv_result_t,
    qve_report_info: *mut sgx_ql_qe_report_info_t,
    supplement_size: uint32_t,
    supplement: *mut uint8_t,
) -> sgx_quote3_error_t {
    println!("hello :)"); // for debug

    if quote.is_null()
        || expiration_check_date == 0
        || collateral_expiration_status.is_null()
        || quote_verification_result.is_null()
        || is_supplement_bad(supplement, supplement_size)
    {
        println!("quote.is_null(): {}", quote.is_null());
        println!("expiration_check_date==0: {}", expiration_check_date == 0);
        println!(
            "collateral_expiration_status.is_null() = {}",
            collateral_expiration_status.is_null()
        );
        println!(
            "quote_verification_result.is_null(): {}",
            quote_verification_result.is_null()
        );
        println!(
            "is_supplemental_data_bad(supplemental_data,supplemental_data_size): {}",
            is_supplement_bad(supplement, supplement_size)
        );

        if !quote_verification_result.is_null() {
            unsafe {
                *quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
            }
        }

        return sgx_quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER;
    }
    println!("param ok :)");

    let quote = unsafe { slice::from_raw_parts(quote, quote_size as usize) };

    if !supplement.is_null() {
        let mut got = 0u32;
        let err = unsafe { sgx_qv_get_quote_supplemental_data_size(&mut got) };
        if err != sgx_quote3_error_t::SGX_QL_SUCCESS || got > supplement_size {
            if !quote_verification_result.is_null() {
                unsafe {
                    *quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
                }
            }

            return sgx_quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    println!("supplement ok");

    println!("qve_report_info.is_null(): {}", qve_report_info.is_null());

    let mut qve_id: sgx_enclave_id_t = 0;
    let mut qve_err = sgx_quote3_error_t::SGX_QL_ERROR_UNEXPECTED;
    let mut status = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut fmspc = [0u8; 6];
    let mut ca_type = [0u8; 10];
    let mut qve_collateral: *mut qve::sgx_ql_qve_collateral_t = ptr::null_mut();

    if !qve_report_info.is_null() {
    } else {
    }

    unsafe {
        sgx_types::sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            quote_collateral,
            expiration_check_date,
            collateral_expiration_status,
            quote_verification_result,
            qve_report_info,
            supplement_size,
            supplement,
        )
    }
}

fn is_supplement_bad(data: *const u8, ell: u32) -> bool {
    (data.is_null() && ell != 0) || (!data.is_null() && ell == 0)
}
