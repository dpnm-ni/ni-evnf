#!/bin/bash
#
# benchmark single vnf with pktgen
# VM1(pktgen) --> VM2 VNF
#

set -e
set -x

VNF_SSH_ADDR="ubuntu@10.10.10.10"
VNF_MAC="00:90:27:f5:58:0c"
OUT_NIC="enp5s0f0"

# default value
NUM_THREADS=16
PKT_SIZE=64
# FIXME: CLONE_SKB > 0 somehow does not work well with 82599 in our exp
CLONE_SKB=0
MEASUREMENT_TIME=60
REST_TIME=5
RESULT_FILE="result_single_vnf.txt"
DST_PORT="9201-9205"
# CIDR for destination IP so that RSS in client can load balance traffic to queues
DST_IPS='192.168.4.0/24'
RATES=( 50 100 200 500 1000 1500 2000 3000 4000 5000 7000 9000 10000)


TEST_CASE=edpi256_1cpu

case ${TEST_CASE} in
    eft64)
        RATES=( 50 100 200 500 1000 1500 2000 3000 4000 5000 7000 8000 9000 10000)
        ;;
    eft512_1vcpu)
        PKT_SIZE=512
        ;;
    eft256_1vcpu)
        PKT_SIZE=256
        ;;
    eft64_1vcpu)
        RATES=( 50 100 200 500 1000 1500 2000 3000)
        ;;
    eft1024_1vcpu)
        NUM_THREADS=4
        PKT_SIZE=1024
        ;;

    # edpi
    ndpi256_1cpu)
        DST_IPS='192.168.6.0/28'
        PKT_SIZE=256
        NUM_THREADS=2
        RATES=( 100 200 500 1000 1500)
        ;;
    edpi256_1cpu)
        DST_IPS='192.168.6.0/28'
        PKT_SIZE=256
        NUM_THREADS=2
        RATES=( 100 200 500 1000 1500 2000 3000 4000 5000 7000 9000)
        ;;

esac

# RATES=( 1500 2000 3000 )

echo ${TEST_CASE} >>  ${RESULT_FILE}
for rate in ${RATES[@]}; do
    # start pktgen on background job
    sudo ./pktgen/pktgen.sh -i ${OUT_NIC} \
                        -m ${VNF_MAC} \
                        -d ${DST_IPS} \
                        -p ${DST_PORT} \
                        -s ${PKT_SIZE} \
                        -c ${CLONE_SKB} \
                        -t ${NUM_THREADS} \
                        -T $(( ${MEASUREMENT_TIME} + 2 * ${REST_TIME} )) \
                        -B ${rate} \
                        -f 1\
                        >> result_single_vnf.txt &

    # wait a little for traffic and VNF to stable, then start measurement
    echo "Traffic rate is ${rate} Mbps" >> ${RESULT_FILE}
    ssh ${VNF_SSH_ADDR} "sleep ${REST_TIME} && mpstat ${MEASUREMENT_TIME} 1" >> ${RESULT_FILE} &

    # wait all child proccesses to finish. 2s more to ensure process are cleaned
    wait

    sleep 2

    # empty line to make result file more readable
    echo "" >> ${RESULT_FILE}

done
