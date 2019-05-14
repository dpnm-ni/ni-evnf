#!/usr/bin/python

import time
import sys
import pyroute2
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address


class EFw(object):
    """docstring for EFw"""
    def __init__(self, iface):
        super(EFw, self).__init__()
        self.iface = iface

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self.mac_str_to_int(_local_mac_str)
        
        self.bpf_fw = BPF(src_file="efw.c", debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_fw = self.bpf_fw.load_func("fw", BPF.XDP)

        self.tb_ip_mac = self.bpf_fw.get_table("tb_ip_mac")
        self.tb_devmap = self.bpf_fw.get_table("tb_devmap")

        ip = pyroute2.IPRoute()
        idx = ip.link_lookup(ifname=iface)[0]
        self.tb_devmap[ct.c_uint32(0)] = ct.c_int(idx)

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
            self.set_tb_ip_mac(int(event.dst_ip), self.mac_str_to_int(dst_mac_str))
            print "IP to MAC: ", event.dst_ip, " - ", dst_mac_str

        self.bpf_fw["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_fw.kprobe_poll()


if __name__ == "__main__":
    iface = "ens4"

    efw = EFw(iface)
    efw.attach_iface()
    efw.open_events()

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
