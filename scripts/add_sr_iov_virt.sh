#!/bin/bash
#
# add guest VM to sr_iov network
#

set -e
set -x

VM_NAME=''
NIC_PCI=''

print_help () {
    echo "script usage: $(basename $0) [-i] [-n]"
    echo "i: virtual machine name (from virsh list)"
    echo "n: NIC PCI address (e.g., 0000:05:10.0)"
}


while getopts ':n:i:' OPTION; do
    case "$OPTION" in
        i)
            VM_NAME="$OPTARG"
            ;;
        n)
            NIC_PCI="$OPTARG"
            ;;
        ?)
            print_help
            exit 1
            ;;
    esac
done

if  [[ ${VM_NAME} == '' ]] ; then
    echo "error: option -i is required"
    print_help
    exit 1
fi
if  [[ ${NIC_PCI} == '' ]] ; then
    echo "error: option -n is required"
    print_help
    exit 1
fi



# e.g.: 0000:05:10.0
NIC_DOMAIN=$(echo ${NIC_PCI} | grep -o "^[0-9]*")
TMP=$(echo ${NIC_PCI} | grep -oP "^${NIC_DOMAIN}:\K.*")
NIC_BUS=$(echo ${TMP} | grep -o "^[0-9]*")
TMP=$(echo ${TMP} | grep -oP "^${NIC_BUS}:\K.*")
NIC_SLOT=$(echo ${TMP} | grep -o "^[0-9]*")
NIC_FUNCTION=$(echo ${TMP} | grep -oP "^${NIC_SLOT}.\K.*")

VM_CONF_FILE_TMP=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c10).xml

SR_IOV_NIC_CONF="<hostdev mode='subsystem' type='pci' managed='yes'> \
        <source> \
            <address domain='0x${NIC_DOMAIN}' bus='0x${NIC_BUS}' slot='0x${NIC_SLOT}' function='0x${NIC_FUNCTION}'/> \
        </source> \
    </hostdev>"

TO_REBOOT_VM=false

sudo virsh dumpxml ${VM_NAME} > ${VM_CONF_FILE_TMP}

# add config
if ! grep -Fq "cpu mode='host-passthrough'" ${VM_CONF_FILE_TMP}; then
    sed -i "s/<cpu>/<cpu mode='host-passthrough'>/g" ${VM_CONF_FILE_TMP}
    TO_REBOOT_VM=true
else
    echo "VM ${VM_NAME} is already configured for cpu host-passthrough"
fi

if ! grep -Fq "hostdev mode='subsystem' type='pci' managed='yes'" ${VM_CONF_FILE_TMP}; then
    # use </device> so that it only happen once...
    sed -i "s|<devices>|<devices>\n${SR_IOV_NIC_CONF}|" ${VM_CONF_FILE_TMP}
    TO_REBOOT_VM=true
else
    echo "VM ${VM_NAME} is already configured for SR_IOV"
fi

# reboot to take effect
if ${TO_REBOOT_VM}; then
    sudo virsh define ${VM_CONF_FILE_TMP}
    sudo virsh shutdown ${VM_NAME}
    sleep 3
    sudo virsh start ${VM_NAME}
fi

rm ${VM_CONF_FILE_TMP}
