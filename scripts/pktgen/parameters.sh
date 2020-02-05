#
# SPDX-License-Identifier: GPL-2.0
# Common parameter parsing for pktgen scripts
#

function usage() {
    echo ""
    echo "Usage: $0 [-vx] -i ethX"
    echo "  -i : (\$DEV)       output interface/device (required)"
    echo "  -s : (\$PKT_SIZE)  packet size"
    echo "  -d : (\$DEST_IP)   destination IP. CIDR (e.g. 198.18.0.0/15) is also allowed"
    echo "  -m : (\$DST_MAC)   destination MAC-addr"
    echo "  -p : (\$DST_PORT)  destination PORT range (e.g. 433-444) is also allowed"
    echo "  -t : (\$THREADS)   threads to start"
    echo "  -f : (\$F_THREAD)  index of first thread (zero indexed CPU number)"
    echo "  -c : (\$SKB_CLONE) SKB clones send before alloc new SKB"
    echo "  -b : (\$BURST)     HW level bursting of SKBs"
    echo "  -B : (\$BANDWIDTH) (Maximum) bandwidth [Mbps] to send"
    echo "  -T : (\$TIME)      time [s] to send packets "
    echo "  -v : (\$VERBOSE)   verbose"
    echo "  -x : (\$DEBUG)     debug"
    echo "  -6 : (\$IP6)       IPv6"
    echo ""
}

##  --- Parse command line arguments / parameters ---
## echo "Commandline options:"
while getopts "B:T:s:i:d:m:p:f:t:c:b:vxh6" option; do
    case $option in
        i) # interface
          export DEV=$OPTARG
	  info "Output device set to: DEV=$DEV"
          ;;
        B)
          export BANDWIDTH=$OPTARG
    info "Bandwidth set to: BANDWIDTH=$BANDWIDTH Mbps"
          ;;
        T)
          export TIME=$OPTARG
    info "Running time set to: TIME=$TIME seconds"
          ;;
        s)
          export PKT_SIZE=$OPTARG
	  info "Packet size set to: PKT_SIZE=$PKT_SIZE bytes"
          ;;
        d) # destination IP
          export DEST_IP=$OPTARG
	  info "Destination IP set to: DEST_IP=$DEST_IP"
          ;;
        m) # MAC
          export DST_MAC=$OPTARG
	  info "Destination MAC set to: DST_MAC=$DST_MAC"
          ;;
        p) # PORT
          export DST_PORT=$OPTARG
	  info "Destination PORT set to: DST_PORT=$DST_PORT"
          ;;
        f)
	  export F_THREAD=$OPTARG
	  info "Index of first thread (zero indexed CPU number): $F_THREAD"
          ;;
        t)
	  export THREADS=$OPTARG
	  info "Number of threads to start: $THREADS"
          ;;
        c)
	  export CLONE_SKB=$OPTARG
	  info "CLONE_SKB=$CLONE_SKB"
          ;;
        b)
	  export BURST=$OPTARG
	  info "SKB bursting: BURST=$BURST"
          ;;
        v)
          export VERBOSE=yes
          info "Verbose mode: VERBOSE=$VERBOSE"
          ;;
        x)
          export DEBUG=yes
          info "Debug mode: DEBUG=$DEBUG"
          ;;
	6)
	  export IP6=6
	  info "IP6: IP6=$IP6"
	  ;;
        h|?|*)
          usage;
          err 2 "[ERROR] Unknown parameters!!!"
    esac
done
shift $(( $OPTIND - 1 ))

if [ -z "$PKT_SIZE" ]; then
    # NIC adds 4 bytes CRC
    export PKT_SIZE=60
    info "Default packet size set to: set to: $PKT_SIZE bytes"
fi

if [ -z "$BANDWIDTH" ]; then
    export BANDWIDTH=10
    info "Default bandwidth set to: $BANDWIDTH Mbps"
fi

if [ -z "$TIME" ]; then
    export TIME=10
    info "Default running time set to: $TIME seconds"
fi

if [ -z "$F_THREAD" ]; then
    # First thread (F_THREAD) reference the zero indexed CPU number
    export F_THREAD=0
fi

if [ -z "$THREADS" ]; then
    export THREADS=1
fi

export L_THREAD=$(( THREADS + F_THREAD - 1 ))

if [ -z "$DEV" ]; then
    usage
    err 2 "Please specify output device"
fi

if [ -z "$DST_MAC" ]; then
    warn "Missing destination MAC address"
fi

if [ -z "$DEST_IP" ]; then
    warn "Missing destination IP address"
fi

if [ ! -d /proc/net/pktgen ]; then
    info "Loading kernel module: pktgen"
    modprobe pktgen
fi