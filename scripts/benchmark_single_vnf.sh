#!/bin/bash
#
# benchmark single vnf with pktgen
# VM1(pktgen) --> VM2 VNF
#

set -e
set -x

VNF_SSH_ADDR="ubuntu@10.10.10.2"
VNF_MAC="62:85:56:1b:e2:13"
OUT_NIC="enp5s0f0"
NUM_THREADS=8
PKT_SIZE=64
MEASUREMENT_TIME=120
REST_TIME=8
RESULT_FILE="result_single_vnf.txt"
DST_PORT="9201-9205"

for rate in 50 100 200 500 1000 1500 2000 3000 4000 5000 7000 9000; do
    # start pktgen on background job
    # CIDR for destination IP so that RSS in client can load balance traffic  to queues
    ./pktgen/pktgen.sh -i ${OUT_NIC} \
                    -m ${VNF_MAC} \
                    -d '192.168.4.0/24' \
                    -p ${DST_PORT} \
                    -s ${PKT_SIZE} \
                    -t ${NUM_THREADS} \
                    -T $(( ${MEASUREMENT_TIME} + 2 * ${REST_TIME} )) \
                    -B ${rate} \
                    >> result_single_vnf.txt &

    # wait a little for traffic and VNF to stable, then start measurement
    sleep 3
    echo "Traffic rate is ${rate} Mbps" >> ${RESULT_FILE}
    ssh ${VNF_SSH_ADDR} "sleep $(( ${REST_TIME} - 3 )) && mpstat ${MEASUREMENT_TIME} 1" >> ${RESULT_FILE}
    sleep ${REST_TIME}

    # wait more to ensure pktgen is stopped
    sleep ${REST_TIME}

    # empty line to make result file more readable
    echo "" >> ${RESULT_FILE}

done
