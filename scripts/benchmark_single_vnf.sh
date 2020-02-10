#!/bin/bash
#
# benchmark single vnf with pktgen
# VM1(pktgen) --> VM2 VNF
#

set -e
set -x

VNF_SSH_ADDR="ubuntu@10.10.10.10"
VNF_MAC="fa:16:3e:52:46:1d"
OUT_NIC="ens4"
NUM_THREADS=1
PKT_SIZE=1024
CLONE_SKB=1000
MEASUREMENT_TIME=60
REST_TIME=5
RESULT_FILE="result_single_vnf.txt"
DST_PORT="9201-9205"

# for rate in 50 100 200 500 1000 1500 2000 3000 4000 5000 7000 9000; do
for rate in 9000; do
    # start pktgen on background job
    # CIDR for destination IP so that RSS in client can load balance traffic  to queues
    sudo ./pktgen/pktgen.sh -i ${OUT_NIC} \
                            -m ${VNF_MAC} \
                            -d '192.168.4.0/32' \
                            -p ${DST_PORT} \
                            -s ${PKT_SIZE} \
                            -c ${CLONE_SKB} \
                            -t ${NUM_THREADS} \
                            -T $(( ${MEASUREMENT_TIME} + 2 * ${REST_TIME} )) \
                            -B ${rate} \
                            -f 1 \
                            >> result_single_vnf.txt &

    # wait a little for traffic and VNF to stable, then start measurement
    sleep 2
    echo "Traffic rate is ${rate} Mbps" >> ${RESULT_FILE}
    ssh ${VNF_SSH_ADDR} "sleep $(( ${REST_TIME} - 2 )) && mpstat ${MEASUREMENT_TIME} 1" >> ${RESULT_FILE}
    sleep ${REST_TIME}

    # wait more to ensure pktgen is stopped
    sleep 2

    # empty line to make result file more readable
    echo "" >> ${RESULT_FILE}

done
