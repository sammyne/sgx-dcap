cmake_minimum_required(VERSION 3.10)

project(hello-world)

include(ExternalProject)

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

add_custom_target(format
    DEPENDS format-${app} format-${enclave}
)

add_custom_target(pack
    COMMAND rm -rf ${PROJECT_BINARY_DIR}/_packed
    COMMAND mkdir ${PROJECT_BINARY_DIR}/_packed
    COMMAND cp ${PROJECT_BINARY_DIR}/app/cargo/release/app ${PROJECT_BINARY_DIR}/_packed/
    COMMAND cp ${PROJECT_BINARY_DIR}/enclave/${enclaveLib} ${PROJECT_BINARY_DIR}/_packed/
    COMMAND cp scripts/* ${PROJECT_BINARY_DIR}/_packed/
    COMMENT "[PACK] pack up app for deployment"
    DEPENDS ${app} ${enclave}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)