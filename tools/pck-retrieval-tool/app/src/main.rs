#![allow(safe_packed_borrows)]

use std::ffi::CString;

use sgx_types::*;
use sgx_urts::SgxEnclave;

mod codec;
mod pck;

use pck::PCK;

extern "C" {
    fn ecall_new_report(
        eid: sgx_enclave_id_t,
        status: *mut sgx_status_t,
        report: *mut sgx_report_t,
        qe3_target: *const sgx_target_info_t,
    ) -> sgx_status_t;
}

fn decode_quote3(quote: &[u8]) {
    // ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L149
    // ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L177
    // ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.9/tools/PCKRetrievalTool/App/App.cpp#L279
    // this quote has type `sgx_quote3_t` and is structured as:
    // sgx_quote3_t {
    //     header: sgx_quote_header_t,
    //     report_body: sgx_report_body_t,
    //     signature_data_len: uint32_t,  // 1116
    //     signature_data {               // 1116 bytes payload
    //         sig_data: sgx_ql_ecdsa_sig_data_t { // 576 = 64x3 +384 header
    //             sig: [uint8_t; 64],
    //             attest_pub_key: [uint8_t; 64],
    //             qe3_report: sgx_report_body_t, //  384
    //             qe3_report_sig: [uint8_t; 64],
    //             sgx_ql_auth_data_t { // 2 + 32 = 34
    //                 size: u16 // observed 32, size of following auth_data
    //                 auth_data: [u8; size]
    //             }
    //             sgx_ql_certification_data_t {/ 2 + 4 + 500
    //                 cert_key_type: uint16_t,
    //                 size: uint32_t, // observed 500, size of following certificateion_data
    //                 certification_data: [u8; size]
    //             }
    //         }
    //     }
    //  }

    let quote3_ptr = quote.as_ptr() as *const sgx_quote3_t;
    let quote3 = unsafe { *quote3_ptr };

    let sig = quote[std::mem::size_of::<sgx_quote3_t>()..].as_ref();
    assert_eq!(
        quote3.signature_data_len as usize,
        sig.len(),
        "invalid sig length"
    );

    // signature_data has a header of sgx_ql_ecdsa_sig_data_t structure
    //let p_sig_data: * const sgx_ql_ecdsa_sig_data_t = quote_signature_data_vec.as_ptr() as _;
    // mem copy
    //let sig_data = unsafe { * p_sig_data };

    // sgx_ql_ecdsa_sig_data_t is followed by sgx_ql_auth_data_t
    // create a new vec for auth_data
    let ql_auth_certification_data_offset = std::mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
    let ql_auth_data_ptr =
        (sig[ql_auth_certification_data_offset..]).as_ptr() as *const sgx_ql_auth_data_t;
    let ql_auth_data = unsafe { *ql_auth_data_ptr };
    //println!("auth_data len = {}", auth_data_header.size);

    let auth_data_offset =
        ql_auth_certification_data_offset + std::mem::size_of::<sgx_ql_auth_data_t>();

    // It should be [0,1,2,3...]
    // defined at https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4605fae1c606de4ff1191719433f77f050f1c33c/QuoteGeneration/quote_wrapper/quote/qe_logic.cpp#L1452
    //let auth_data_vec: Vec<u8> = quote_signature_data_vec[auth_data_offset..auth_data_offset + auth_data_header.size as usize].into();
    //println!("Auth data:\n{:?}", auth_data_vec);

    let ql_certification_data_offset = auth_data_offset + ql_auth_data.size as usize;
    let ql_certification_data_ptr =
        sig[ql_certification_data_offset..].as_ptr() as *const sgx_ql_certification_data_t;
    let ql_certification_data = unsafe { *ql_certification_data_ptr };

    //println!("certification data offset = {}", temp_cert_data_offset);
    //println!("certification data size = {}", temp_cert_data.size);

    let certification_info_data_offset =
        ql_certification_data_offset + std::mem::size_of::<sgx_ql_certification_data_t>();

    //println!("cert info offset = {}", cert_info_offset);
    // this should be the last structure
    assert_eq!(
        sig.len(),
        certification_info_data_offset + ql_certification_data.size as usize
    );

    // ref: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.9/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L58
    //assert_eq!(
    //    ql_certification_data.cert_key_type,
    //    sgx_ql_cert_key_type_t::PPID_RSA3072_ENCRYPTED as u16,
    //    "expect cert key of type PPID_RSA3072_ENCRYPTED"
    //);

    let tail_content = sig[certification_info_data_offset..].as_ref();
    let enc_ppid_len = 384;
    let enc_ppid: &[u8] = &tail_content[0..enc_ppid_len];
    let pce_id: &[u8] = &tail_content[enc_ppid_len..enc_ppid_len + 2];
    let cpu_svn: &[u8] = &tail_content[enc_ppid_len + 2..enc_ppid_len + 2 + 16];
    let pce_isvsvn: &[u8] = &tail_content[enc_ppid_len + 2 + 16..enc_ppid_len + 2 + 18];
    println!("          EncPPID: {:02x?}", enc_ppid);
    println!("           PCE_ID: {:02x?}", pce_id);
    println!("    TCBr - CPUSVN: {:02x?}", cpu_svn);
    println!("TCBr - PCE_ISVSVN: {:02x?}", pce_isvsvn);
    println!("            QE_ID: {:02x?}", quote3.header.user_data);

    /*
    // convert as sgx_ql_ppid_rsa3072_encrypted_cert_info_t produces wrong result.
    let info = unsafe {
        let v = sig[certification_info_data_offset..].as_ptr()
            as *const sgx_ql_ppid_rsa3072_encrypted_cert_info_t;
        *v
    };

    const QE_ID_LEN: usize = 16;
    println!("          EncPPID: {:02x?}", info.enc_ppid);
    println!("    TCBr - CPUSVN: {:02x?}", info.cpu_svn.svn);
    println!("TCBr - PCE_ISVSVN: {:02x?}", info.pce_info.pce_isv_svn);
    println!("           PCE_ID: {:02x?}", &info.pce_info.pce_id);
    println!(
        "            QE_ID: {:02x?}",
        &quote3.header.user_data[..QE_ID_LEN]
    );
    */
}

fn error_out_if_not_ok(status: sgx_status_t, tip: &str) -> Result<(), String> {
    if status == sgx_status_t::SGX_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, status))
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

fn qe3_error_out_if_not_ok(err: sgx_quote3_error_t, tip: &str) -> Result<(), String> {
    if err == sgx_quote3_error_t::SGX_QL_SUCCESS {
        return Ok(());
    }

    Err(format!("[-] {}: {}", tip, err))
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
        qe3_error_out_if_not_ok(err, "sgx_ql_set_path").unwrap();
    }

    let enclave = new_enclave(&args[1])
        .map_err(|err| format!("new enclave: {}", err))
        .unwrap();
    println!("[+] done new enclave: {}", enclave.geteid());

    let quote = generate_quote(enclave.geteid()).expect("generate quote");

    //println!("quote size: {}", quote.len());
    //for (i, v) in quote.iter().enumerate() {
    //    print!("{:02x}", v);
    //    if (i + 1) % 64 == 0 {
    //        println!();
    //    }
    //}
    //println!();

    //decode_quote3(quote.as_slice());
    let pck = PCK::must_from_quote3(quote.as_slice());
    let pck_json = serde_json::to_string(&pck).expect("json marshaling");
    println!("PCK: {}",pck_json);
}
