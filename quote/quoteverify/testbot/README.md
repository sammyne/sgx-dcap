# testbot

PCCS 服务测试机器人。

## 环境
- SGX 2.12 + DCAP 1.9

## 快速开始

```bash
rm -rf build
mkdir build
cd build

cmake -DCMAKE_BUILD_TYPE=Prerelease ..
make pack

cd _pack

# 进入容器
bash play.sh

# 更新 renew_pccs.sh 脚本的 PCCS_ADDR 为 PCCS 服务的地址

# 生成并验证 quote
bash run.sh
```

正常的输出如下（测试时的 PCCS 地址为 `172.17.0.4:443`）
```bash
setting PCCS address to 172.17.0.4:443
setting USE_SECURE_CERT to FALSE
[+] init enclave successful 2!
fns.create_dcap_quote():: start
[+] sgx_qe_get_quote_size ok: quote_size=4578
[+] sgx_qe_get_quote => success
[enclave+] sgx_qv_get_quote_supplemental_data_size ok
- after ocall_sgx_qv_verify_quote, supplemental_data_ok=1
Verification completed with Non-terminal result: SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
[+] ecall_generate_then_verify_dcap_quote done...
```
