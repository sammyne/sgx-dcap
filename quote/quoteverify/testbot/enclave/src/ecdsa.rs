use sgx_tcrypto::SgxEccHandle;
use sgx_types::*;

pub fn generate_key() -> SgxResult<(sgx_ec256_private_t, sgx_ec256_public_t)> {
    let h = SgxEccHandle::new();
    h.open()?;

    h.create_key_pair()
}
