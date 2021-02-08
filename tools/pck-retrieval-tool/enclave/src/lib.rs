#![no_std]

extern crate sgx_tstd as std;

use sgx_types::*;

#[no_mangle]
pub extern "C" fn ecall_new_report(
    report: *mut sgx_report_t,
    qe3_target: *const sgx_target_info_t,
) -> sgx_status_t {
    let data = sgx_report_data_t::default();

    unsafe { sgx_create_report(qe3_target, &data as *const sgx_report_data_t, report) }
}
