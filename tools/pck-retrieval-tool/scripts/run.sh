#!/bin/bash

export LD_PRELOAD=$PWD/libdcap_quoteprov.so.1
./app enclave.signed.so
