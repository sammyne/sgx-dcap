#!/bin/bash

remote=https://hub.fastgit.org/intel/SGXDataCenterAttestationPrimitives.git
rev=DCAP_1.9

workdir=$(dirname ${BASH_SOURCE[0]})
vendorDir=$workdir/vendor/SGXDataCenterAttestationPrimitives
qvDir=$vendorDir/QuoteVerification

cd $workdir

#rm -rf $vendorDir
#git clone -b $rev $remote $vendorDir
#
#cp $workdir/scripts/prepare_sgxssl.sh $qvDir
#
#cd $qvDir
#make

cp $qvDir/dcap_quoteverify/linux/libsgx_dcap_quoteverify.so $workdir/_lib
