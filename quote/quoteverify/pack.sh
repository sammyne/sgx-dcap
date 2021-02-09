#!/bin/bash

set -e

workdir=$(dirname ${BASH_SOURCE[0]})

# make workdir absolute
cd $workdir
workdir=$PWD

outDir=$workdir/_packed

rm -rf $outDir
mkdir $outDir

cd $workdir

bash build_legacy.sh

cp _lib/* $outDir/

cd $workdir/testbot

rm -rf build
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Prerelease ..
make pack

cp -r _packed/* $outDir/
