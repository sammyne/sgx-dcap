use sgx_types::*;
use sgx_urts::SgxEnclave;

mod qe3;

extern "C" {
    fn ecall_generate_then_verify_dcap_quote(
        eid: sgx_enclave_id_t,
        err: *mut c_int,
    ) -> sgx_status_t;
}

fn new_enclave(enclave_path: &str) -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // [DEPRECATED since v2.6] Step 1: try to retrieve the launch token saved by last transaction
    // if there is no token, then create a new one.
    //

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    const DEBUG: i32 = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    let enclave = SgxEnclave::create(
        enclave_path,
        DEBUG,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )?;

    // [DEPRECATED since v2.6] Step 3: save the launch token if it is updated

    Ok(enclave)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("missing enclave path");
        std::process::exit(-1);
    }

    let enclave = match new_enclave(&args[1]) {
        Ok(r) => {
            println!("[+] init enclave successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] init enclave failed {:?}!", x);
            return;
        }
    };

    let mut err: c_int = 0;
    let status = unsafe { ecall_generate_then_verify_dcap_quote(enclave.geteid(), &mut err) };

    if status != sgx_status_t::SGX_SUCCESS {
        panic!(
            "[-] ecall_generate_then_verify_dcap_quote failed with invalid status: {:?}",
            status
        );
    }
    if err != 0 {
        panic!(
            "[-] ecall_generate_then_verify_dcap_quote failed with invalid error code: {}",
            err
        );
    }

    println!("[+] ecall_generate_then_verify_dcap_quote done...");

    enclave.destroy();
}