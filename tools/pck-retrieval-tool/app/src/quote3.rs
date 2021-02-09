use std::env;

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

pub fn set_qpl_path(path: &str) {
    let qpl_path = if path.starts_with("/") {
        path.to_string()
    } else {
        // change to absolute path
        env::current_dir()
            .expect("fail to get cwd")
            .join(path)
            .to_str()
            .unwrap()
            .to_string()
    };

    env::set_var("LD_PRELOAD", qpl_path);

    // setting LD_PRELOAD can render the sgx_ql_set_path below redundant
    //{
    //    let quoteprov_path =
    //        CString::new(opts.qpl_path).expect("failed to set 'quoteprov_path'");
    //    let err = unsafe {
    //        sgx_ql_set_path(
    //            sgx_ql_path_type_t::SGX_QL_QPL_PATH,
    //            quoteprov_path.as_ptr() as *const char,
    //        )
    //    };
    //    errors::qe3_error_out_if_not_ok(err, "sgx_ql_set_path").unwrap();
    //}
}
