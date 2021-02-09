use sgx_types::*;

use crate::{ecdsa, quote};

#[no_mangle]
pub fn ecall_generate_then_verify_dcap_quote() -> c_int {
    let (_, pubkey) = match ecdsa::generate_key() {
        Ok(v) => v,
        Err(err) => {
            println!("generate_key failed: {:?}", err);
            return err as i32;
        }
    };

    let quote = match quote::new_dcap_quote(&pubkey) {
        Ok(v) => v,
        Err(err) => {
            println!("new_dcap_quote failed: {}", err);
            return -1;
        }
    };

    match quote::qv_verify_quote3(quote.as_slice()) {
        Ok(_) => {}
        Err(err) => {
            println!("[-] qv_verify_quote3: {}", err);
            return -2;
        }
    }

    0
}
