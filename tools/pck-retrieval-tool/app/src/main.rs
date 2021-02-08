extern crate sgx_urts;

use std::ffi::CString;

use sgx_types::*;
use sgx_urts::SgxEnclave;

extern "C" {
    fn ecall_new_report(
        eid: sgx_enclave_id_t,
        status: *mut sgx_status_t,
        report: *mut sgx_report_t,
        qe3_target: *const sgx_target_info_t,
    ) -> sgx_status_t;
}

fn error_out_if_not_ok(status: sgx_status_t, tip: &str) -> Result<(), String> {
    if status == sgx_status_t::SGX_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, status))
}

fn qe3_error_out_if_not_ok(err: sgx_quote3_error_t, tip: &str) -> Result<(), String> {
    if err == sgx_quote3_error_t::SGX_QL_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, err))
}

fn new_enclave(enclave_path: &str) -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // [DEPRECATED since v2.6] Step 1: try to retrieve the launch token saved by last transaction
    // if there is no token, then create a new one.

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    const DEBUG: i32 = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        enclave_path,
        DEBUG,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )

    // [DEPRECATED since v2.6] Step 3: save the launch token if it is updated
}

fn generate_quote(eid: sgx_enclave_id_t) -> Result<Vec<u8>, String> {
    let qe3_target = {
        let mut out = sgx_target_info_t::default();
        let err = unsafe { sgx_qe_get_target_info(&mut out as *mut sgx_target_info_t) };
        qe3_error_out_if_not_ok(err, "get target info")?;

        out
    };

    let app_report = {
        let mut status = sgx_status_t::SGX_SUCCESS;
        let mut out = sgx_report_t::default();
        let err = unsafe { ecall_new_report(eid, &mut status, &mut out, &qe3_target) };
        error_out_if_not_ok(err, "new report error out")?;
        error_out_if_not_ok(status, "new report status")?;

        out
    };

    let quote_size = unsafe {
        let mut out = 0u32;
        let err = sgx_qe_get_quote_size(&mut out);
        qe3_error_out_if_not_ok(err, "calc QE quote size")?;

        out
    };

    let mut quote = vec![0u8; quote_size as usize];
    let err = unsafe { sgx_qe_get_quote(&app_report, quote_size, quote.as_mut_ptr()) };
    qe3_error_out_if_not_ok(err, "get QE quote")?;

    Ok(quote)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("missing enclave path");
        std::process::exit(-1);
    }

    {
        let quoteprov_path = CString::new("libdcap_quoteprov.so.1")
            .expect("failed to set 'quoteprov_path'");
        let err = unsafe {
            sgx_ql_set_path(
                sgx_ql_path_type_t::SGX_QL_QPL_PATH,
                quoteprov_path.as_ptr() as *const char,
            )
        };
        qe3_error_out_if_not_ok(err, "sgx_ql_set_path").unwrap();
    }

    let enclave = new_enclave(&args[1])
        .map_err(|err| format!("new enclave: {}", err))
        .unwrap();
    println!("[+] done new enclave: {}", enclave.geteid());

    let quote = generate_quote(enclave.geteid()).expect("generate quote");
    println!("{:?}", quote);
}
