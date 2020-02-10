#!/bin/bash
#
# modify NIC setup to enable XDP in the guest VM
#

set -e
set -x

VM_NAME=''

while getopts ':i:' OPTION; do
    case "$OPTION" in
        i)
            VM_NAME="$OPTARG"
            ;;
        ?)
            echo "script usage: $(basename $0) -i virtual machine name (from virsh list)"
            exit 1
            ;;
    esac
done

if  [[ ${VM_NAME} == '' ]] ; then
    echo "error: option -i is required"
    echo "script usage: $(basename $0) -i virtual machine name (from virsh list)"
    exit 1
fi


VM_CONF_FILE_TMP=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c10).xml
sudo virsh dumpxml ${VM_NAME} > ${VM_CONF_FILE_TMP}

NUM_VCPUS=$(sudo virsh vcpucount --maximum --live ${VM_NAME})
NUM_QUEUE=$(( ${NUM_VCPUS} * 2 ))

if grep -Fq "interface type='vhostuser'" ${VM_CONF_FILE_TMP}; then
    NIC_CONF="<driver queues='${NUM_QUEUE}'>\n \
              <guest csum='off'/> \n \
              </driver>"
else
    NIC_CONF="<driver name='vhost' queues='${NUM_QUEUE}'>\n \
              <guest csum='off'/> \n \
              </driver>"
fi

CPU_CONF="<cpu mode='host-passthrough'>"

TO_REBOOT_VM=false

# add config
if ! grep -Fq "queues='${NUM_QUEUE}'" ${VM_CONF_FILE_TMP}; then
    sed -i "/<mac address=.*\/>$/ a ${NIC_CONF}" ${VM_CONF_FILE_TMP}
    TO_REBOOT_VM=true
else
    echo "VM ${VM_NAME} is already configured for xdp"
fi

if ! grep -Fq "cpu mode='host-passthrough'" ${VM_CONF_FILE_TMP}; then
    sed -i "s/<cpu>/<cpu mode='host-passthrough'>/g" ${VM_CONF_FILE_TMP}
    TO_REBOOT_VM=true
else
    echo "VM ${VM_NAME} is already configured for cpu host-passthrough"
fi

# reboot to take effect
if ${TO_REBOOT_VM}; then
    sudo virsh define ${VM_CONF_FILE_TMP}
    sudo virsh shutdown ${VM_NAME}
    sleep 3
    sudo virsh start ${VM_NAME}
fi

rm ${VM_CONF_FILE_TMP}
