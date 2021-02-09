use serde::Serialize;
use std::convert::TryInto;

use sgx_types::*;

#[derive(Serialize)]
pub struct PCK {
    #[serde(serialize_with = "crate::codec::serialize_slice")]
    encrypted_ppid: [u8; 384],
    #[serde(serialize_with = "crate::codec::serialize_slice")]
    pce_id: [u8; 2],
    #[serde(serialize_with = "crate::codec::serialize_slice")]
    cpu_svn: [u8; 16],
    #[serde(serialize_with = "crate::codec::serialize_slice")]
    pce_isvsvn: [u8; 2],
    #[serde(serialize_with = "crate::codec::serialize_slice")]
    qe_id: [u8; 16],
}

impl PCK {
    pub fn must_from_quote3(quote: &[u8]) -> Self {
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

        // sgx_ql_ecdsa_sig_data_t is followed by sgx_ql_auth_data_t
        // create a new vec for auth_data
        let ql_auth_certification_data_offset = std::mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        let ql_auth_data_ptr =
            (sig[ql_auth_certification_data_offset..]).as_ptr() as *const sgx_ql_auth_data_t;
        let ql_auth_data = unsafe { *ql_auth_data_ptr };

        let auth_data_offset =
            ql_auth_certification_data_offset + std::mem::size_of::<sgx_ql_auth_data_t>();

        // It should be [0,1,2,3...]
        // defined at https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4605fae1c606de4ff1191719433f77f050f1c33c/QuoteGeneration/quote_wrapper/quote/qe_logic.cpp#L1452

        let ql_certification_data_offset = auth_data_offset + ql_auth_data.size as usize;
        let ql_certification_data_ptr =
            sig[ql_certification_data_offset..].as_ptr() as *const sgx_ql_certification_data_t;
        let ql_certification_data = unsafe { *ql_certification_data_ptr };

        let certification_info_data_offset =
            ql_certification_data_offset + std::mem::size_of::<sgx_ql_certification_data_t>();

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

        let info = sig[certification_info_data_offset..].as_ref();

        let mut taken = 0usize;
        let mut must_take = |n: usize| -> &[u8] {
            let out = &info[taken..(taken + n)];
            taken += n;
            out
        };

        let encrypted_ppid: [u8; 384] =
            must_take(384).try_into().expect("invalid encrypted PPID");
        let pce_id: [u8; 2] = must_take(2).try_into().expect("invalid PCE ID");
        let cpu_svn: [u8; 16] = must_take(16).try_into().expect("invalid CPU SVN");
        let pce_isvsvn: [u8; 2] = must_take(2).try_into().expect("invalid PCE ISV SVN");
        let qe_id: [u8; 16] = quote3.header.user_data[..16]
            .try_into()
            .expect("invalid QE ID");
        //println!("          EncPPID: {:02x?}", encrypted_ppid);
        //println!("           PCE_ID: {:02x?}", pce_id);
        //println!("    TCBr - CPUSVN: {:02x?}", cpu_svn);
        //println!("TCBr - PCE_ISVSVN: {:02x?}", pce_isvsvn);
        //println!("            QE_ID: {:02x?}", quote3.header.user_data);
        //println!("            QE_ID: {:02x?}", qe_id);

        Self {
            encrypted_ppid,
            pce_id,
            cpu_svn,
            pce_isvsvn,
            qe_id,
        }

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
}
