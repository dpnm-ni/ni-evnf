#!/usr/bin/python

import time
import sys
import socket, os
import threading
import argparse
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address

import pyximport; pyximport.install()
from cy_edpi import CyEDPI


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="iface to listen")
    args = parser.parse_args()

    # edpi = EDPI(iface)
    edpi = CyEDPI(args.iface)
    edpi.attach_iface()
    edpi.open_events()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    # a separated thread to poll event
    def _event_poll():
        try:
            while True:
                edpi.poll_events()
        except:
            pass
    event_poll = threading.Thread(target=_event_poll)
    event_poll.daemon = True
    event_poll.start()

    # listen to ndpi for detected flow
    try:
        while 1:
            edpi.add_detected_flow()
    # d_flow = FLowId()
    # try:
    #     while 1:
    #         if (edpi.conn.recv_into(d_flow)):
    #             edpi.add_detected_flow(d_flow)
                # print "new flow: ", d_flow.dst_ip, d_flow.src_ip, \
                #     d_flow.dst_port, d_flow.src_port, d_flow.protocol

    except KeyboardInterrupt:
        pass

    finally:
        edpi.detach_iface()
        edpi.conn.close()
        print "Done"
