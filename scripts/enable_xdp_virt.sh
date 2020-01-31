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

NUM_VCPUS=$(sudo virsh vcpucount --maximum --live ${VM_NAME})
NUM_QUEUE=$(( ${NUM_VCPUS} * 2 ))

NIC_CONF="<driver name='vhost' queues='${NUM_QUEUE}'>\n \
          <guest csum='off'/> \n \
          </driver>"

TO_REBOOT_VM=false

# add config
sudo virsh dumpxml ${VM_NAME} > ${VM_CONF_FILE_TMP}
if ! grep -Fq "queues='${NUM_QUEUE}'" ${VM_CONF_FILE_TMP}; then
    sed -i "/<mac address=.*\/>$/ a ${NIC_CONF}" ${VM_CONF_FILE_TMP}
    sudo virsh define ${VM_CONF_FILE_TMP}
    TO_REBOOT_VM=true
else
    echo "VM ${VM_NAME} is already configured"
fi
rm ${VM_CONF_FILE_TMP}


# reboot to take effect
if ${TO_REBOOT_VM}; then
    sudo virsh shutdown ${VM_NAME}
    sleep 3
    sudo virsh start ${VM_NAME}
fi