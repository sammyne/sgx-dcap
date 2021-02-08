#!/bin/bash

workingDir=$(dirname ${BASH_SOURCE[0]})

cd ${workingDir}

app=test-pck-retrieval-tool

docker stop $app

# --add-host ps.sgx.trustedservices.intel.com:3.95.74.173	暂时解决国内 intel 验证服务无法使用的问题
docker run -it --rm --name $app 	\
	--network=none 									\
	--device /dev/sgx 							\
	-v ${PWD}:/workspace 						\
	-w /workspace 									\
  sammyne/sgx-dcap:2.12.100.3-dcap1.9.100.3-ubuntu18.04 bash
