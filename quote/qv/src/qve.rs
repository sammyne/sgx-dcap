use std::ffi::CString;
use std::sync::RwLock;

use lazy_static::lazy_static;
use sgx_types::*;
use sgx_urts::*;

#[derive(Default)]
pub struct QvE {
    load_policy: sgx_ql_request_policy_t,
    enclave_id: sgx_enclave_id_t,
    attr: sgx_misc_attribute_t,
}

#[repr(C)]
pub struct sgx_ql_qve_collateral_t {
    pub version: uint32_t, // version = 1.  PCK Cert chain is in the Quote.
    pub pck_crl_issuer_chain: *mut c_char,
    pub pck_crl_issuer_chain_size: uint32_t,
    pub root_ca_crl: *mut c_char, // Root CA CRL
    pub root_ca_crl_size: uint32_t,
    pub pck_crl: *mut c_char, // PCK Cert CRL
    pub pck_crl_size: uint32_t,
    pub tcb_info_issuer_chain: *mut c_char,
    pub tcb_info_issuer_chain_size: uint32_t,
    pub tcb_info: *mut c_char, // TCB Info structure
    pub tcb_info_size: uint32_t,
    pub qe_identity_issuer_chain: *mut c_char,
    pub qe_identity_issuer_chain_size: uint32_t,
    pub qe_identity: *mut c_char, // QE Identity Structure
    pub qe_identity_size: uint32_t,
}

lazy_static! {
    static ref GLOBAL_QVE: RwLock<QvE> = RwLock::new(QvE::default());
    static ref GLOBAL_QVE_PATH: RwLock<String> = RwLock::new(String::new());
}

pub fn get_path() -> String {
    {
        let v = GLOBAL_QVE_PATH
            .read()
            .expect("fail to lock GLOBAL_QVE_PATH for read");
        if (*v).len() == 0 {
            return v.clone();
        }
    }

    //const DEFAULT_ENCLAVE_PATH: 'static &str = "libsgx_qve.signed.so";
    "/usr/lib/x86_64-linux-gnu/libsgx_qve.signed.so".to_string()
}

pub fn load() -> SgxResult<sgx_enclave_id_t> {
    let mut w = GLOBAL_QVE.write().expect("lock GLOBAL_QVE for writing");

    if w.enclave_id != 0 {
        return Ok(w.enclave_id);
    }

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // [DEPRECATED since v2.6] Step 1: try to retrieve the launch token saved by last transaction
    // if there is no token, then create a new one.

    let enclave_path = CString::new(get_path()).expect("fail to get enclave path");

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    const DEBUG: i32 = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };

    println!("create qve ...");
    match sgx_urts::rsgx_create_enclave(
        enclave_path.as_c_str(),
        DEBUG,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    ) {
        Err(err) => {
            if err == sgx_status_t::SGX_ERROR_OUT_OF_EPC {
                return Err(sgx_status_t::SGX_ERROR_OUT_OF_EPC);
            }

            println!("error out with status: {:?}", err);
            return Err(err);
        }
        Ok(v) => w.enclave_id = v,
    }
    w.attr = misc_attr;
    println!("create qve done ...");

    Ok(w.enclave_id)

    // [DEPRECATED since v2.6] Step 3: save the launch token if it is updated
}

pub fn set_load_policy(policy: sgx_ql_request_policy_t) {
    let mut w = GLOBAL_QVE.write().expect("lock GLOBAL_QVE for writing");
    w.load_policy = policy;

    if policy == sgx_ql_request_policy_t::SGX_QL_EPHEMERAL {
        unload(true);
    }
}

pub fn set_path(path: &str) -> bool {
    if path.len() > 260 {
        return false;
    }

    let mut w = GLOBAL_QVE_PATH
        .write()
        .expect("fail to get lock for global qve path");
    *w = path.to_string();

    true
}

pub fn unload(force: bool) {
    let mut w = GLOBAL_QVE.write().expect("lock GLOBAL_QVE for writing");

    if w.enclave_id == 0 || (!force && w.load_policy == sgx_ql_request_policy_t::SGX_QL_PERSISTENT)
    {
        return;
    }

    println!("unload qve {} ...", w.enclave_id);
    let _ = rsgx_destroy_enclave(w.enclave_id);

    w.enclave_id = 0;
    w.attr = sgx_misc_attribute_t::default();
}
