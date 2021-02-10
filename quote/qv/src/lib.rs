use std::slice;

use sgx_types::*;

pub use sgx_types::sgx_qv_get_quote_supplemental_data_size;

pub fn verify_quote(
    quote: *const uint8_t,
    quote_size: uint32_t,
    quote_collateral: *const sgx_ql_qve_collateral_t,
    expiration_check_date: time_t,
    collateral_expiration_status: *mut uint32_t,
    quote_verification_result: *mut sgx_ql_qv_result_t,
    p_qve_report_info: *mut sgx_ql_qe_report_info_t,
    supplemental_data_size: uint32_t,
    supplemental_data: *mut uint8_t,
) -> sgx_quote3_error_t {
    println!("hello :)"); // for debug

    if quote.is_null()
        || expiration_check_date == 0
        || collateral_expiration_status.is_null()
        || quote_verification_result.is_null()
        || is_supplemental_data_bad(supplemental_data, supplemental_data_size)
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
            is_supplemental_data_bad(supplemental_data, supplemental_data_size)
        );

        if !quote_verification_result.is_null() {
            unsafe {
                *quote_verification_result =
                    sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED as u32;
            }
        }

        return sgx_quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER;
    }

    let quote = unsafe { slice::from_raw_parts(quote, quote_size as usize) };

    unsafe {
        sgx_types::sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
        )
    }
}

fn is_supplemental_data_bad(data: *const u8, ell: u32) -> bool {
    (data.is_null() && ell != 0) || (!data.is_null() && ell == 0)
}
