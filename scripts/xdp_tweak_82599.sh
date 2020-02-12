#!/bin/bash
#
# tweak 82599 (ixgbe) for xdp
#

set -e
set -x

NIC=ens7
DUMMY_IP=192.168.149.12
NUM_CPUS=$(nproc)

# enable JIT
sysctl net/core/bpf_jit_enable=1

# create a dummy IP for NIC (eVNF implementation need that)
nic_state=$(cat /sys/class/net/${NIC}/operstate)
if [[ ${nic_state} != "up" ]]; then
    ifconfig ${NIC} ${DUMMY_IP} netmask 255.255.255.0 up
fi

# stop irqbalance
service irqbalance stop

# manually assign affinity
CPU=0
cd /sys/class/net/${NIC}/device/msi_irqs
for IRQ in *; do
    echo $CPU > /proc/irq/$IRQ/smp_affinity_list

    CPU=$(( ${CPU} + 1 ))
    if [[ ${CPU} == ${NUM_CPUS} ]]; then
        CPU=0
    fi
done
