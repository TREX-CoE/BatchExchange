#! /bin/bash

# create build path
BUILD_PATH="cbuild"
mkdir -p $BUILD_PATH
cd $BUILD_PATH

# execute cmake to prepare build process with make
cmake ..
cmake .
