#!/bin/bash

set -e
set -x


# the list consider sibling & numa
TO_ENABLE_CPUS=(0 2 4 6 )
NIC=enp5s0f0

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
