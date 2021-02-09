use sgx_types::*;

use crate::errors;

extern "C" {
    fn ecall_new_report(
        eid: sgx_enclave_id_t,
        status: *mut sgx_status_t,
        report: *mut sgx_report_t,
        qe3_target: *const sgx_target_info_t,
    ) -> sgx_status_t;
}

pub fn generate_quote(eid: sgx_enclave_id_t) -> Result<Vec<u8>, String> {
    let qe3_target = {
        let mut out = sgx_target_info_t::default();
        let err = unsafe { sgx_qe_get_target_info(&mut out as *mut sgx_target_info_t) };
        errors::qe3_error_out_if_not_ok(err, "get target info")?;

        out
    };

    let app_report = {
        let mut status = sgx_status_t::SGX_SUCCESS;
        let mut out = sgx_report_t::default();
        let err = unsafe { ecall_new_report(eid, &mut status, &mut out, &qe3_target) };
        errors::error_out_if_not_ok(err, "new report error out")?;
        errors::error_out_if_not_ok(status, "new report status")?;

        out
    };

    let quote_size = unsafe {
        let mut out = 0u32;
        let err = sgx_qe_get_quote_size(&mut out);
        errors::qe3_error_out_if_not_ok(err, "calc QE quote size")?;

        out
    };

    let mut quote = vec![0u8; quote_size as usize];
    let err = unsafe { sgx_qe_get_quote(&app_report, quote_size, quote.as_mut_ptr()) };
    errors::qe3_error_out_if_not_ok(err, "get QE quote")?;

    Ok(quote)
}
