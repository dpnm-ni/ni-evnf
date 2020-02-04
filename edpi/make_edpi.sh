#!/bin/bash
#
# edpi make script
#

set -e
set -x

TOP_DIR=`pwd`
EDPI_READER_HOME=${TOP_DIR}/edpi_reader
NDPI_HOME=${TOP_DIR}/nDPI

make_all=false
only_hook_and_config=false

while getopts ':ai:' OPTION; do
    case "$OPTION" in
        a)
            make_all=true
            ;;
        i)
            only_hook_and_config=true
            ;;
        ?)
            echo "script usage: $(basename $0) [-a] [-i]"
            echo "-a: hook, init & make all"
            echo "-i: hook and config only"
            echo "default: make edpi only"
            exit 1
            ;;
    esac
done

# install required packages
sudo apt-get install -y build-essential \
                        autogen \
                        automake \
                        autoconf \
                        libtool \
                        gcc \
                        libpcap-dev

# sync edpi_reader source
cp -r ${EDPI_READER_HOME} ${NDPI_HOME}

cd ${NDPI_HOME}

# make edpi only
if [[ $make_all == false && $only_hook_and_config == false ]]; then
    cd edpi_reader
    make
    ln -sf edpi_reader ${EDPI_READER_HOME}/edpi_reader
    exit 0
fi

# apply the edpi patch
git reset --hard
cp ${EDPI_READER_HOME}/edpi_hook.patch ${NDPI_HOME}/edpi_hook.patch
git apply edpi_hook.patch
rm edpi_hook.patch

# create build file
./autogen.sh
./configure

if [[ ${only_hook_and_config} == true ]]; then
    exit 0
fi

# make all
make
ln -sf ${NDPI_HOME}/edpi_reader/edpi_reader ${EDPI_READER_HOME}/edpi_reader

if [[ ${make_all} == true ]]; then
    ln -sf ${NDPI_HOME}/example/ndpiReader ${EDPI_READER_HOME}/ndpiReader
fi
