#!/bin/bash
#
# benchmark single vnf with pktgen
# VM1(pktgen) --> VM2 VNF
#

set -e
set -x


# the list consider sibling & numa
TO_ENABLE_CPUS=(0 2 4 6 )
# nproc only return number of online cpu
MAX_CPU_IDX=23
NIC=enp5s0f0
DUMMY_IP=192.168.149.12/24

NUM_CPUS=${#TO_ENABLE_CPUS[@]}

nic_state=$(cat /sys/class/net/${NIC}/operstate)
if [[ ${nic_state} != "up" ]]; then
    ip link set ${NIC} up
fi

# Disable all CPU, except TO_ENABLE_CPUS and cpu 0.
# CPU 0 is also alway online and cannot modified
# see: https://www.kernel.org/doc/html/latest/core-api/cpu_hotplug.html
for cpu in $( seq 1 $MAX_CPU_IDX ); do
    echo 0 > /sys/devices/system/cpu/cpu${cpu}/online
done
for cpu in ${TO_ENABLE_CPUS[@]}; do
    if [[ ${cpu} == 0 ]]; then
        continue
    fi
    echo 1 > /sys/devices/system/cpu/cpu${cpu}/online
done

# enable JIT
sysctl net/core/bpf_jit_enable=1

nic_state=$(cat /sys/class/net/${NIC}/operstate)
if [[ ${nic_state} != "up" ]]; then
    ip link set ${NIC} up
    ip addr add ${DUMMY_IP} dev ${NIC}
fi

# set number of NIC's queue to the number of CPUs + 1
sudo ethtool -L ${NIC} combined $(( ${NUM_CPUS} * 2))

# stop irqbalance #to manually assign affinity
service irqbalance stop
idx=0
cd /sys/class/net/${NIC}/device/msi_irqs/
for IRQ in *; do
    echo ${TO_ENABLE_CPUS[$idx]} | sudo tee /proc/irq/${IRQ}/smp_affinity_list

    idx=$(( ${idx} + 1 ))
    if [[ ${idx} == ${NUM_CPUS} ]]; then
        idx=0
    fi
done
