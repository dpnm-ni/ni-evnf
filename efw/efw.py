#!/usr/bin/python

import time
import sys
import pyroute2
import argparse
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address


class EFW(object):
    """docstring for EFW"""
    def __init__(self, iface, bpf_src="efw.c"):
        super(EFW, self).__init__()
        self.iface = iface

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self.mac_str_to_int(_local_mac_str)
        
        self.bpf_fw = BPF(src_file=bpf_src, debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_fw = self.bpf_fw.load_func("fw", BPF.XDP)

        self.tb_ip_mac = self.bpf_fw.get_table("tb_ip_mac")
        self.tb_tcp_dest_lookup = self.bpf_fw.get_table("tb_tcp_dest_lookup")
        self.tb_subnet_allow = self.bpf_fw.get_table("tb_subnet_allow")
        self.tb_devmap = self.bpf_fw.get_table("tb_devmap")
        self.tb_prog_array = self.bpf_fw.get_table("tb_prog_array")

        ip = pyroute2.IPRoute()
        idx = ip.link_lookup(ifname=iface)[0]
        self.tb_devmap[ct.c_uint32(0)] = ct.c_int(idx)

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

    def add_port(self, port, mode):
        k = self.tb_tcp_dest_lookup.Key(port)
        if mode == "allow":
            leaf = self.tb_tcp_dest_lookup.Leaf(1)
        elif mode == "block":
            leaf = self.tb_tcp_dest_lookup.Leaf(2)
        else:
            print "warning: unsupported port mode: ", mode
            exit(1)

        self.tb_tcp_dest_lookup[k] = leaf

    def add_allow_subnet(self, subnet):
        k = self.tb_subnet_allow.Key(*subnet)
        leaf = self.tb_subnet_allow.Leaf(1)
        self.tb_subnet_allow[k] = leaf


    def attach_iface(self):
        self.bpf_fw.attach_xdp(self.iface, self.fn_fw, 0)

    def detach_iface(self):
        self.bpf_fw.remove_xdp(self.iface, 0)

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

        self.bpf_fw["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_fw.kprobe_poll()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="iface to listen")
    args = parser.parse_args()

    efw = EFW(args.iface)
    efw.attach_iface()
    efw.open_events()

    efw.add_port(80, "allow")
    efw.add_allow_subnet((24, (192, 168, 4, 0)))
    # k = efw.tb_subnet_allow.Key(24, (192, 168, 4, 4))
    # print "val: ", efw.tb_subnet_allow[k]

    print "eBPF prog Loaded"
    sys.stdout.flush()

    try:
        while 1:
            efw.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        efw.detach_iface()
        print "Done"
