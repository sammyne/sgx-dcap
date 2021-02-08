# Hello World example without CMake

## Environment
- CMake >=3.17
- libcurl4-openssl-dev

## Quickstart

```bash
rm -rf build
mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Prerelease ..
make run
```

## Head Ups
- app should link the APIs (such as `sgx_qe_get_quote`) implemented by the tailored libdcap_quoteprov.so.1 rather than that by /usr/lib/x86_64-linux-gnu/libsgx_dcap_ql.so.1. Otherwise, the EncPPID would be empty.
  - Our solution is to make use of `LD_PRELOAD=$PWD/libdcap_quoteprov.so.1` to prioritize the tailored libdcap_quoteprov.so.1 built from intel/SGXDataCenterAttestationPrimitives/tools/PCKRetrievalTool/

## TODO
- Why the `ql_certification_data.cert_key_type` isn't `sgx_ql_cert_key_type_t::PPID_RSA3072_ENCRYPTED`?

## References
- Intel® Software Guard Extensions (Intel® SGX) Data Center Attestation Primitives: ECDSA Quote Library API - March, 2020
- [Platform Software Management with SGX quote helper daemon set]
- [Intel SGX Provisioning Certification Service for ECDSA Attestation]
- [Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP): A Quick Install Guide]
- [dcap-pckretrieval](https://github.com/apache/incubator-teaclave-sgx-sdk/tree/master/samplecode/dcap-pckretrieval)

[Platform Software Management with SGX quote helper daemon set]: https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-out-of-proc-attestation
[Intel SGX Provisioning Certification Service for ECDSA Attestation]: https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v3
[Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP): A Quick Install Guide]: https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html
