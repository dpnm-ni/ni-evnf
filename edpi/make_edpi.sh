#!/bin/bash
#
# edpi make script
#

set -e
set -x

TOP_DIR=`pwd`
EDPI_READER_HOME=${TOP_DIR}/edpi_reader
NDPI_HOME=${TOP_DIR}/nDPI

make_edpi_only=false
only_hook_and_config=false

while getopts ':ec:' OPTION; do
    case "$OPTION" in
        e)
            make_edpi_only=true
            ;;
        c)
            only_hook_and_config=true
            ;;
        ?)
            echo "script usage: $(basename $0) [-e] [-c]"
            echo "-e: make edpi only"
            echo "-c: hook and config only"
            echo "default: make all"
            exit 1
            ;;
    esac
done

if [[ $make_edpi_only == false ]]; then
    # install required packages
    sudo apt-get install -y build-essential \
                            autogen \
                            automake \
                            autoconf \
                            libtool \
                            gcc \
                            libpcap-dev

    # sync edpi_reader source
    rm -rf ${NDPI_HOME}/edpi_reader
    cp -r ${EDPI_READER_HOME} ${NDPI_HOME}
fi

# make edpi only
if [[ $make_edpi_only == true && $only_hook_and_config == false ]]; then
    # remove softlink first
    rm -f ${EDPI_READER_HOME}/edpi_reader

    cd ${NDPI_HOME}/edpi_reader
    make clean
    cp ${EDPI_READER_HOME}/* .
    make
    ln -sf -sf ${NDPI_HOME}/edpi_reader/edpi_reader ${EDPI_READER_HOME}/edpi_reader
    exit 0
fi

cd ${NDPI_HOME}
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

