#![allow(safe_packed_borrows)]

use std::ffi::CString;

use sgx_types::*;
use sgx_urts::SgxEnclave;

mod codec;
mod errors;
mod pck;
mod quote3;

use pck::PCK;

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

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("missing enclave path");
        std::process::exit(-1);
    }

    {
        let quoteprov_path =
            CString::new("libdcap_quoteprov.so.1").expect("failed to set 'quoteprov_path'");
        let err = unsafe {
            sgx_ql_set_path(
                sgx_ql_path_type_t::SGX_QL_QPL_PATH,
                quoteprov_path.as_ptr() as *const char,
            )
        };
        errors::qe3_error_out_if_not_ok(err, "sgx_ql_set_path").unwrap();
    }

    let enclave = new_enclave(&args[1])
        .map_err(|err| format!("new enclave: {}", err))
        .unwrap();
    println!("[+] done new enclave: {}", enclave.geteid());

    let quote = quote3::generate_quote(enclave.geteid()).expect("generate quote");

    //println!("quote size: {}", quote.len());
    //for (i, v) in quote.iter().enumerate() {
    //    print!("{:02x}", v);
    //    if (i + 1) % 64 == 0 {
    //        println!();
    //    }
    //}
    //println!();

    let pck = PCK::must_from_quote3(quote.as_slice());
    let pck_json = serde_json::to_string(&pck).expect("json marshaling");
    println!("PCK: {}", pck_json);
}
