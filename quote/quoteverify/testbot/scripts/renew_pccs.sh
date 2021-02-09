#!/bin/bash

PCCS_ADDR=172.17.0.3:443

qcnl_conf=/etc/sgx_default_qcnl.conf
#qcnl_conf=${PWD}/sgx_default_qcnl.conf

echo "setting PCCS address to $PCCS_ADDR"
#sed -i "s!//[^/]*/!//${PCCS_ADDR}/!" ${qcnl_conf}
sed -i "s!PCCS_URL=https://.*!PCCS_URL=https://${PCCS_ADDR}/v3/!" ${qcnl_conf}

echo "setting USE_SECURE_CERT to FALSE"
sed -i "s/USE_SECURE_CERT=TRUE/USE_SECURE_CERT=FALSE/g" ${qcnl_conf}
