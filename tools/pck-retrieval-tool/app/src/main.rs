#![allow(safe_packed_borrows)]

use std::ffi::CString;

use clap::Clap;

use sgx_types::*;
use sgx_urts::SgxEnclave;

mod codec;
mod errors;
mod pck;
mod quote3;

use pck::PCK;

#[derive(Clap)]
#[clap(version = "1.9", author = "sammyne")]
struct Opts {
    #[clap(
        default_value = "enclave.signed.so",
        help = "path of enclave to use",
        long = "enclave",
        short = "e"
    )]
    enclave_path: String,
    #[clap(help = "path to output PCK info", long = "pck", short = "p")]
    pck_out_path: Option<String>,
    #[clap(
        default_value = "libdcap_quoteprov.so.1",
        help = "path libdcap_quoteprov.so.1",
        long = "qpl"
    )]
    qpl_path: String,
    #[clap(help = "path to output quote", long = "quote", short = "q")]
    quote_out_path: Option<String>,
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

fn main() {
    let opts = Opts::parse();
    println!("-------------------------------------------------");
    println!("enclave path: {}", opts.enclave_path);
    println!("    qpl path: {}", opts.qpl_path);
    println!("-------------------------------------------------");

    quote3::set_qpl_path(&opts.qpl_path);

    let enclave = new_enclave(&opts.enclave_path)
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
