#!/bin/bash
#
# compile pf_ring af_xdp and kernel module
#

set -e
set -x

KERNEL_VERSION=5.1.2
TOP_DIR=`pwd`

# install necessary packages
sudo apt update
sudo apt install -y clang llvm libelf-dev gcc-multilib build-essential \
                    pkg-config bison flex

# install kernel bpf headers and libs
# https://www.ntop.org/guides/pf_ring/modules/af_xdp.html
if ! test -f /usr/local/include/bpf/xsk.h; then
    wget http://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz
    tar xvf linux-${KERNEL_VERSION}.tar.xz > /dev/null
    cd linux-${KERNEL_VERSION}/tools/lib/bpf
    make
    sudo make install_lib && sudo make install_headers
    rm ${TOP_DIR}/linux-${KERNEL_VERSION}.tar.xz
    rm -rf ${TOP_DIR}/linux-${KERNEL_VERSION}
fi

# add bpf share libs
echo "/usr/lib64" | sudo tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
echo "/usr/local/lib64" | sudo tee -a /etc/ld.so.conf.d/x86_64-linux-gnu.conf
sudo ldconfig

# compile pfring kernel
# https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#kernel-module-installation
cd ${TOP_DIR}/PF_RING/kernel
make
sudo make install

# pf ring usersand libs
cd ${TOP_DIR}/PF_RING/userland/lib
./configure && make
sudo make install

# compile pf ring af xdp
cd ${TOP_DIR}/PF_RING/userland
./configure --enable-xdp
make
