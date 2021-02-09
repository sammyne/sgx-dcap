use sgx_types::*;

pub use sgx_types::sgx_qv_get_quote_supplemental_data_size;

pub fn qv_verify_quote(
    p_quote: *const uint8_t,
    quote_size: uint32_t,
    p_quote_collateral: *const sgx_ql_qve_collateral_t,
    expiration_check_date: time_t,
    p_collateral_expiration_status: *mut uint32_t,
    p_quote_verification_result: *mut sgx_ql_qv_result_t,
    p_qve_report_info: *mut sgx_ql_qe_report_info_t,
    supplemental_data_size: uint32_t,
    p_supplemental_data: *mut uint8_t,
) -> sgx_quote3_error_t {
    unsafe {
        sgx_types::sgx_qv_verify_quote(
            p_quote,
            quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
        )
    }
}
