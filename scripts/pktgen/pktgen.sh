#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Simple example:
#  * pktgen sending with single thread and single interface
#  * flow variation via random UDP source port
#
basedir=`dirname $0`
source ${basedir}/functions.sh
root_check_run_with_sudo "$@"

# Parameter parsing via include
# - go look in parameters.sh to see which setting are avail
# - required param is the interface "-i" stored in $DEV
source ${basedir}/parameters.sh
#
# Set some default params, if they didn't get set
if [ -z "$DEST_IP" ]; then
    [ -z "$IP6" ] && DEST_IP="198.18.0.42" || DEST_IP="FD00::1"
fi
[ -z "$CLONE_SKB" ] && CLONE_SKB="0"
# Example enforce param "-m" for dst_mac
[ -z "$DST_MAC" ] && usage && err 2 "Must specify -m dst_mac"

if [ -n "$DEST_IP" ]; then
    validate_addr${IP6} $DEST_IP
    read -r DST_MIN DST_MAX <<< $(parse_addr${IP6} $DEST_IP)
fi
if [ -n "$DST_PORT" ]; then
    read -r UDP_DST_MIN UDP_DST_MAX <<< $(parse_ports $DST_PORT)
    validate_ports $UDP_DST_MIN $UDP_DST_MAX
fi

# Base Config, value are per-thread
PPS=$(( ${BANDWIDTH} * 10**6 / 8 / ${PKT_SIZE} / ${THREADS} ))
DELAY=$(( 10**9 / ${PPS} )) # Zero means max speed
COUNT=$(( ${TIME} * ${PPS} )) # Zeno mean infinite
# COUNT=0


# Flow variation random source port between min and max
UDP_SRC_MIN=9
UDP_SRC_MAX=9

# General cleanup everything since last run
# (especially important if other threads were configured by other scripts)
pg_ctrl "reset"

# Threads are specified with parameter -t value in $THREADS
for ((thread = $F_THREAD; thread <= $L_THREAD; thread++)); do
    # The device name is extended with @name, using thread number to
    # make then unique, but any name will do.
    dev=${DEV}@${thread}
    pg_thread $thread "rem_device_all"
    pg_thread $thread "add_device" $dev

    # Notice config queue to map to cpu (mirrors smp_processor_id())
    # It is beneficial to map IRQ /proc/irq/*/smp_affinity 1:1 to CPU number
    pg_set $dev "flag QUEUE_MAP_CPU"

    # How many packets to send (zero means indefinitely)
    pg_set $dev "count $COUNT"

    # Reduce alloc cost by sending same SKB many times
    # - this obviously affects the randomness within the packet
    pg_set $dev "clone_skb $CLONE_SKB"

    # Set packet size
    pg_set $dev "pkt_size $PKT_SIZE"

    # Delay between packets (zero means max speed)
    pg_set $dev "delay $DELAY"

    # Flag example disabling timestamping
    pg_set $dev "flag NO_TIMESTAMP"

    # Destination
    pg_set $dev "dst_mac $DST_MAC"
    pg_set $dev "dst${IP6}_min $DST_MIN"
    pg_set $dev "dst${IP6}_max $DST_MAX"

    if [ -n "$DST_PORT" ]; then
        # Single destination port or random port range
        pg_set $dev "flag UDPDST_RND"
        pg_set $dev "udp_dst_min $UDP_DST_MIN"
        pg_set $dev "udp_dst_max $UDP_DST_MAX"
    fi

    # Setup random UDP port src range
    pg_set $dev "flag UDPSRC_RND"
    pg_set $dev "udp_src_min $UDP_SRC_MIN"
    pg_set $dev "udp_src_max $UDP_SRC_MAX"
done

# start_run
echo "Running..." >&2
pg_ctrl "start" &
sleep $(( $TIME + 1 ))
pg_ctrl "stop"
echo "Done" >&2

# Print results
for ((thread = $F_THREAD; thread <= $L_THREAD; thread++)); do
    dev=${DEV}@${thread}
    echo "Device: $dev"
    cat /proc/net/pktgen/$dev | grep -A2 "Result:"
done
