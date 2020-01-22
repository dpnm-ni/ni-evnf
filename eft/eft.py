#!/usr/bin/python

import time
import sys
import pyroute2
import threading
import argparse
import socket
import struct
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address


class EFT(object):
    """docstring for EFT"""
    def __init__(self, iface, bpf_src="eft.c"):
        super(EFT, self).__init__()
        self.iface = iface

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self.mac_str_to_int(_local_mac_str)

        self.bpf_ft = BPF(src_file=bpf_src, debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_ft = self.bpf_ft.load_func("ft", BPF.XDP)

        self.tb_ip_mac = self.bpf_ft.get_table("tb_ip_mac")
        self.tb_flow_stats = self.bpf_ft.get_table("tb_flow_stats")
        self.tb_prog_array = self.bpf_ft.get_table("tb_prog_array")

    def print_stats(self):
        print "\n-----------------------------------------------------------\n" \
              "proto, src_ip:src_port -> dst_ip:dst_port  : packets, bytes\n" \
              "-----------------------------------------------------------"
        for flow_id, flow_stat in self.tb_flow_stats.items():
            print "%d, %s:%d -> %s:%d \t: %d, %d" %(
                    flow_id.ip_proto,
                    self.int_to_ip(flow_id.src_ip),
                    flow_id.src_port,
                    self.int_to_ip(flow_id.dst_ip),
                    flow_id.dst_port,
                    flow_stat.pkt_cnt,
                    flow_stat.byte_cnt
                )

    def ip_to_int(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]


    def int_to_ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def set_next_vnf(self, fd):
        self.tb_prog_array[ct.c_int(0)] = ct.c_int(fd)

    def clear_next_vnf(self):
        del self.tb_prog_array[ct.c_int(0)]

    def mac_str_to_int(self, mac_str):
        mac_arr = mac_str.split(':')
        tmp =""
        for i in range(0, 6):
            tmp += mac_arr[i]
        return int(tmp, 16)

    def set_tb_ip_mac(self, ip, mac):
        k = self.tb_ip_mac.Key(ip)
        leaf = self.tb_ip_mac.Leaf(mac)
        self.tb_ip_mac[k] = leaf

    def attach_iface(self):
        self.bpf_ft.attach_xdp(self.iface, self.fn_ft, 0)

    def detach_iface(self):
        self.bpf_ft.remove_xdp(self.iface, 0)

    def open_events(self):
        def _process_event(ctx, data, size):
            class Event(ct.Structure):
                _fields_ =  [("dst_ip", ct.c_uint32)]

            event = ct.cast(data, ct.POINTER(Event)).contents
            dst_ip_str = str(IPv4Address(event.dst_ip))
            dst_mac_str = get_mac_address(ip=dst_ip_str)
            if dst_mac_str is not None:
                self.set_tb_ip_mac(int(event.dst_ip), self.mac_str_to_int(dst_mac_str))
                print "IP to MAC: ", event.dst_ip, " - ", dst_mac_str
            else:
                print "warning: fail to get mac of: ", dst_ip_str

        self.bpf_ft["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_ft.kprobe_poll()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("-t", "--timeout", default=60, type=int, help="flow timeout in seconds")
    parser.add_argument("-i", "--interval", default=2, type=int, help="update interval in seconds")
    args = parser.parse_args()

    eft = EFT(args.iface)
    eft.attach_iface()
    eft.open_events()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    def _event_poll():
        try:
            while True:
                eft.poll_events()
        except:
            pass
    event_poll = threading.Thread(target=_event_poll)
    event_poll.daemon = True
    event_poll.start()

    try:
        while True:
            time.sleep(args.interval)
            eft.print_stats()


    except KeyboardInterrupt:
        pass

    finally:
        eft.detach_iface()
        print "Done"
