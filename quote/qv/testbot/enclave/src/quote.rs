use std::prelude::v1::*;

use sgx_types::*;

use std::{mem, ptr};

extern "C" {
    fn ocall_sgx_qe_get_quote(
        ret_val: *mut sgx_quote3_error_t,
        p_report: *const sgx_report_t,
        p_quote: *mut u8,
        quote_max_size: u32,
        p_quote_size: *mut u32,
    ) -> sgx_status_t;

    fn ocall_sgx_qe_get_target_info(
        ret_val: *mut sgx_quote3_error_t,
        ret_ti: *mut sgx_target_info_t,
    ) -> sgx_status_t;

    fn ocall_sgx_qv_verify_quote(
        err: *mut sgx_quote3_error_t,
        quote: *const u8,
        quote_size: u32,
        expiration_check_date: time_t,
        collateral_expiration_status: *mut u32,
        quote_verification_result: *mut sgx_ql_qv_result_t,
        qve_report_info: *mut sgx_ql_qe_report_info_t,
        supplemental_data: *mut sgx_ql_qv_supplemental_t,
        supplemental_data_ok: *mut u8,
    ) -> sgx_status_t;
}

#[allow(dead_code)]
struct Quote3VerifyAddon {
    expiration_check_date: i64,
    collateral_expiration_status: u32,
    quote_verification_result: sgx_ql_qv_result_t,
    supplemental_data: Option<sgx_ql_qv_supplemental_t>,
}

pub fn new_dcap_quote(pub_k: &sgx_ec256_public_t) -> Result<Vec<u8>, String> {
    println!("fns.create_dcap_quote():: start");
    let mut ret: Vec<u8> = Vec::new();

    // Workflow:
    // (1) ocall to get the target_info structure (ti)
    // (1.5) get sigrl
    // (2) call rsgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti
    //// QE3
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut rt: sgx_quote3_error_t = sgx_quote3_error_t::SGX_QL_SUCCESS;
    let res = unsafe {
        ocall_sgx_qe_get_target_info(
            &mut rt as *mut sgx_quote3_error_t,
            &mut ti as *mut sgx_target_info_t,
        )
    };
    if res != sgx_status_t::SGX_SUCCESS {
        println!("[-] ocall_sgx_qe_get_target_info failed: {:?}", res);
        return Err("unknown".to_string());
    }
    if rt != sgx_quote3_error_t::SGX_QL_SUCCESS {
        println!("[-] ocall_sgx_qe_get_target_info failed: {:?}", rt);
        return Err("invalid sgx_quote3_error_t".to_string());
    }

    // (1.5) get sigrl
    // ignore this step for now

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx; // by mesatee
    pub_k_gx.reverse(); // by mesatee
    let mut pub_k_gy = pub_k.gy; // by mesatee
    pub_k_gy.reverse(); // by mesatee
    report_data.d[..32].clone_from_slice(&pub_k_gx); // by mesatee
    report_data.d[32..].clone_from_slice(&pub_k_gy); // by mesatee

    let mut ae_report =
        sgx_tse::rsgx_create_report(&ti, &report_data).map_err(|err| err.to_string())?;

    // generate random data => quote_nonce
    // let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    // let mut os_rng = mayfail! {
    //     rng =<< os::SgxRng::new();
    //     ret rng
    // }?;
    // os_rng.fill_bytes(&mut quote_nonce.rand);

    // (3) Generate the quote
    // Args:
    //       0. return error status: sgx_quote3_error_t
    //       1. report: ptr 432bytes
    //       2. quote:  ptr quote_max_size
    //       3. quote_max_size:  u32
    //       4. quote_size:  ptr u32, real quote size
    const RET_QUOTE_BUF_LEN: u32 = 1 << 13; // 8192
    let quote_max_size: u32 = RET_QUOTE_BUF_LEN; // ok
    let mut quote: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize]; // ok
    let mut quote_size: u32 = 0; // ok

    let res = unsafe {
        ocall_sgx_qe_get_quote(
            &mut rt as *mut sgx_quote3_error_t,
            &mut ae_report as *const sgx_report_t,
            &mut quote[0],
            quote_max_size,
            &mut quote_size,
        )
    };
    // error handler
    if res != sgx_status_t::SGX_SUCCESS {
        println!("[-] ocall_sgx_qe_get_quote failed: {:?}", res);
        return Err("sgx".to_string());
    }
    if rt != sgx_quote3_error_t::SGX_QL_SUCCESS {
        println!("[-] ocall_sgx_qe_get_quote failed: {:?}", rt);
        return Err("ql".to_string());
    }

    for i in 0..quote_size {
        ret.push(quote[i as usize]);
    }

    Ok(ret)
}

pub fn qv_verify_quote3(quote: &[u8]) -> Result<(), String> {
    let mut qve_report_info = {
        let mut info = sgx_ql_qe_report_info_t::default();
        // @TODO: randomize the nonce
        info.nonce.rand = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let status = unsafe { sgx_self_target(&mut info.app_enclave_target_info) };

        match status {
            sgx_status_t::SGX_SUCCESS => {}
            _ => {
                return Err(format!(
                    "[-] sgx_self_target failed status: {}",
                    status.as_str()
                ))
            }
        }

        info
    };

    let addon = qv_verify_quote3_with_report(quote, &mut qve_report_info)?;

    let status = verify_report(&qve_report_info, quote, &addon);
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status.as_str().to_string());
    }

    Ok(())
}

fn qv_verify_quote3_with_report(
    quote: &[u8],
    report: *mut sgx_ql_qe_report_info_t,
) -> Result<Quote3VerifyAddon, String> {
    let mut supplemental_data_ok = 0u8;
    let mut supplemental_data = sgx_ql_qv_supplemental_t::default();

    // 2022/02/02 00:00:00 UTC as unix seconds 1643786148
    // @TODO: read from config
    let expiration_check_date = 1643786148i64;

    // call DCAP quote verify library for quote verification
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let mut qve_err = sgx_quote3_error_t::SGX_QL_ERROR_UNEXPECTED;
    let status = unsafe {
        ocall_sgx_qv_verify_quote(
            &mut qve_err,
            quote.as_ptr(),
            quote.len() as u32,
            expiration_check_date,
            &mut collateral_expiration_status,
            &mut quote_verification_result as *mut sgx_ql_qv_result_t,
            report,
            &mut supplemental_data,
            &mut supplemental_data_ok,
        )
    };

    println!(
        "- after ocall_sgx_qv_verify_quote, supplemental_data_ok={}",
        supplemental_data_ok
    );

    if status != sgx_status_t::SGX_SUCCESS {
        println!("[-] ocall_sgx_qv_verify_quote failed status: {:?}", status);
        return Err(status.as_str().to_string());
    }

    if qve_err != sgx_quote3_error_t::SGX_QL_SUCCESS {
        println!(
            "[-] ocall_sgx_qv_verify_quote failed qe3 error: {:?}",
            qve_err
        );
        return Err(qve_err.as_str().to_string());
    }
    //@TODO: check supplemental_data_ok

    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => println!("Verification completed successfully."),
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => println!(
            "Verification completed with Non-terminal result: {:?}",
            quote_verification_result,
        ),
        _ => return Err(format!("{:?}", quote_verification_result)),
    };

    let supplemental_data = if supplemental_data_ok == 0 {
        None
    } else {
        Some(supplemental_data)
    };

    let quote3_addon = Quote3VerifyAddon {
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        supplemental_data,
    };

    Ok(quote3_addon)
}

fn verify_report(
    report: &sgx_ql_qe_report_info_t,
    quote: &[u8],
    addon: &Quote3VerifyAddon,
) -> sgx_status_t {
    let mut report_data_got: sgx_sha256_hash_t = [0u8; 32];

    unsafe {
        let ret = sgx_verify_report(&report.qe_report as *const sgx_report_t);
        if ret != sgx_status_t::SGX_SUCCESS {
            return ret;
        }

        let mut hash: sgx_sha_state_handle_t = ptr::null_mut();
        let status = sgx_sha256_init(&mut hash as *mut sgx_sha_state_handle_t);
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        //report_data = SHA256([nonce || quote || expiration_check_date || expiration_status
        //    || verification_result || supplemental_data] || 32 - 0x00<92>s)

        //nonce
        let status = sgx_sha256_update(
            report.nonce.rand.as_ptr(),
            report.nonce.rand.len() as u32,
            hash,
        );
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        //quote
        let status = sgx_sha256_update(quote.as_ptr(), quote.len() as u32, hash);
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        //expiration_check_date
        let status = sgx_sha256_update(
            addon.expiration_check_date.to_ne_bytes().as_ptr(),
            // i64 should be the type of addon.expiration_check_date
            mem::size_of::<i64>() as u32,
            hash,
        );
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        //collateral_expiration_status
        let status = sgx_sha256_update(
            addon.collateral_expiration_status.to_ne_bytes().as_ptr(),
            mem::size_of::<u32>() as u32,
            hash,
        );
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        // verification_result
        let status = sgx_sha256_update(
            (addon.quote_verification_result as u32)
                .to_ne_bytes()
                .as_ptr(),
            mem::size_of::<sgx_ql_qv_result_t>() as u32,
            hash,
        );
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }

        // supplemental_data
        if let Some(data) = addon.supplemental_data {
            let status = sgx_sha256_update(
                &data as *const _ as *const u8,
                mem::size_of::<sgx_ql_qv_supplemental_t>() as u32,
                hash,
            );
            if status != sgx_status_t::SGX_SUCCESS {
                return status;
            }
        }

        //get the hashed report_data
        let status = sgx_sha256_get_hash(hash, &mut report_data_got);
        if status != sgx_status_t::SGX_SUCCESS {
            return status;
        }
    }

    if &report.qe_report.body.report_data.d[..32] != &report_data_got {
        println!(
            "qe hash: {:?}, got hash: {:?}",
            &report.qe_report.body.report_data.d[..32],
            &report_data_got
        );
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t::SGX_SUCCESS
}
