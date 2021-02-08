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

## References
- Intel® Software Guard Extensions (Intel® SGX) Data Center Attestation Primitives: ECDSA Quote Library API - March, 2020
- [Platform Software Management with SGX quote helper daemon set]
- [Intel SGX Provisioning Certification Service for ECDSA Attestation]
- [Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP): A Quick Install Guide]

[Platform Software Management with SGX quote helper daemon set]: https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-out-of-proc-attestation
[Intel SGX Provisioning Certification Service for ECDSA Attestation]: https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v3
[Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP): A Quick Install Guide]: https://software.intel.com/content/www/us/en/develop/articles/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html
