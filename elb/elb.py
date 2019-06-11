#!/usr/bin/python

import time
import sys
import threading
import random
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address
from pysnmp.hlapi import *


class ELB(object):
    """docstring for ELB"""
    def __init__(self, iface, s_ips_str, bpf_src="elb.c"):
        super(ELB, self).__init__()
        self.iface = iface
        self.s_ips_str = s_ips_str
        self.s_ips = [int(IPv4Address(s_ip_str)) for s_ip_str in s_ips_str]
        self.HASHMAP_SIZE = 256
        self.s_weights = [self.HASHMAP_SIZE/len(s_ips_str) for _ in range(0, len(s_ips_str))]
        self.s_frees = [0 for _ in range(0, self.HASHMAP_SIZE)]

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self.mac_str_to_int(_local_mac_str)
        
        self.bpf_lb = BPF(src_file=bpf_src, debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_HASHMAP_SIZE=%s" % self.HASHMAP_SIZE,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_lb = self.bpf_lb.load_func("lb", BPF.XDP)

        self.tb_ip_mac = self.bpf_lb.get_table("tb_ip_mac")
        self.tb_server_ips = self.bpf_lb.get_table("tb_server_ips")

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
        self.bpf_lb.attach_xdp(self.iface, self.fn_lb, 0)

    def detach_iface(self):
        self.bpf_lb.remove_xdp(self.iface, 0)

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

        self.bpf_lb["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_lb.kprobe_poll()

    def get_servers_load(self):
        numServers = len(self.s_ips_str)
        s_frees = [0 for i in range(0, numServers)]
        for i in range(0, numServers):
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                    CommunityData('public', mpModel=0),
                    UdpTransportTarget((self.s_ips_str[i], 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('.1.3.6.1.4.1.2021.10.1.3.1')) ) )

            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
                oid, val = varBinds[0]
                s_frees[i] = 10 - min(10, int(round(10*float(val))))
        return s_frees

    def cal_s_weights_w_load(self, s_frees):
        s_weights_w_load = [0 for _ in range(0, len(self.s_weights))]
        for i in range(0, len(self.s_weights)):
            s_weights_w_load[i] = self.s_weights[i] * s_frees[i]
        return s_weights_w_load

    def cal_s_hashmap(self, s_weights_w_load):
        new_s_hashmap = []
        sum_weight = sum(s_weights_w_load)
        for i in range(0, len(self.s_ips_str)):
            num_of_sched = max(1, int(s_weights_w_load[i] * self.HASHMAP_SIZE / sum_weight))
            new_s_hashmap.extend([self.s_ips[i] for _ in range(0, num_of_sched)])

        if len(new_s_hashmap) < self.HASHMAP_SIZE:
            new_s_hashmap.extend([self.s_ips[-1] for _ in range(len(new_s_hashmap), self.HASHMAP_SIZE)])

        random.shuffle(new_s_hashmap)
        return new_s_hashmap
        # return random.shuffle(new_s_hashmap)

    def update_s_hashmap(self, new_s_hashmap):
        for i in range(0, len(new_s_hashmap)):
            k = self.tb_server_ips.Key(i)
            leaf = self.tb_server_ips.Leaf(new_s_hashmap[i])
            # print "update mapping: ", i, ": ", new_s_hashmap[i]
            self.tb_server_ips[k] = leaf
        self.new_s_hashmap = new_s_hashmap


if __name__ == "__main__":
    iface = "ens4"
    # s_ips_str = [u"192.168.4.10", u"192.168.4.16", u"192.168.4.8"]
    s_ips_str = [u"192.168.4.10", u"192.168.4.16"]

    elb = ELB(iface, s_ips_str)
    s_frees = elb.get_servers_load()
    print "s_frees: ", s_frees
    s_weights_w_load = elb.cal_s_weights_w_load(s_frees)
    print "s_weights_w_load: ", s_weights_w_load
    new_s_hashmap = elb.cal_s_hashmap(s_weights_w_load)
    print "new_s_hashmap: ", new_s_hashmap
    elb.update_s_hashmap(new_s_hashmap)

    # exit()

    elb.attach_iface()
    elb.open_events()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    # a separated thread to recaculate server distribution
    # based on new server weights
    # def _event_poll():
    #     try:
    #         while True:
    #             edpi.poll_events()
    #     except:
    #         pass
    # event_poll = threading.Thread(target=_event_poll)
    # event_poll.daemon = True
    # event_poll.start()

    try:
        while True:
            elb.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        elb.detach_iface()
        print "Done"
