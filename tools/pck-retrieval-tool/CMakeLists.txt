cmake_minimum_required(VERSION 3.18)

project(pck-retrieval-tool)

set(dcapCxxDir ${PROJECT_SOURCE_DIR}/third_party/SGXDataCenterAttestationPrimitives)

include(cmake/git.cmake)
include(cmake/sgx.cmake)

#set(appPath ${CMAKE_CURRENT_SOURCE_DIR}/app)
set(enclavePath ${CMAKE_CURRENT_SOURCE_DIR}/enclave)

set(app app)
set(enclave enclave)

set(config ${enclavePath}/enclave.config.xml)
set(edl enclave.edl)
set(enclaveLib enclave.signed.so)
set(key ${enclavePath}/isv.pem)

add_subdirectory(enclave)
add_subdirectory(app)

add_custom_target(format-${PROJECT_NAME}
    DEPENDS format-${app} format-${enclave}
)

set(qplDir ${dcapCxxDir}/tools/PCKRetrievalTool)

add_custom_target(qpl
    COMMAND make clean && make
    COMMENT "[BUILD] quote prov library"
    WORKING_DIRECTORY ${qplDir}
)

add_custom_target(pack
    COMMAND rm -rf ${PROJECT_BINARY_DIR}/_packed
    COMMAND mkdir ${PROJECT_BINARY_DIR}/_packed
    COMMAND cp ${PROJECT_BINARY_DIR}/app/cargo/release/app ${PROJECT_BINARY_DIR}/_packed/
    COMMAND cp ${PROJECT_BINARY_DIR}/enclave/${enclaveLib} ${PROJECT_BINARY_DIR}/_packed/
    COMMAND cp ${qplDir}/libdcap_quoteprov.so.1 ${PROJECT_BINARY_DIR}/_packed/
    COMMAND cp scripts/* ${PROJECT_BINARY_DIR}/_packed/
    COMMENT "[PACK] pack up app for deployment"
    DEPENDS ${app} ${enclave} qpl
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_custom_target(run
    COMMAND ./app ${enclaveLib}
    DEPENDS pack
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/_packed
)
