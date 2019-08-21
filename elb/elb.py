#!/usr/bin/python

import time
import sys
import threading
import random
import argparse
import ctypes as ct
import netifaces as ni
from bcc import BPF
from ipaddress import IPv4Address
from getmac import get_mac_address
from pysnmp.hlapi import *


class ELB(object):
    """docstring for ELB"""
    def __init__(self, iface, servers, bpf_src="elb.c"):
        super(ELB, self).__init__()
        self.iface = iface
        self.servers = [IPv4Address(server) for server in servers]
        self.HASHMAP_SIZE = 256
        self.server_weights = [self.HASHMAP_SIZE/len(self.servers) for _ in range(0, len(self.servers))]
        self.server_frees = [0 for _ in range(0, self.HASHMAP_SIZE)]

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self._mac_str_to_int(_local_mac_str)

        self.bpf_lb = BPF(src_file=bpf_src, debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_HASHMAP_SIZE=%s" % self.HASHMAP_SIZE,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_lb = self.bpf_lb.load_func("lb", BPF.XDP)

        self.tb_ip_mac = self.bpf_lb.get_table("tb_ip_mac")
        self.tb_server_ips = self.bpf_lb.get_table("tb_server_ips")

    def _mac_str_to_int(self, mac_str):
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
                self.set_tb_ip_mac(int(event.dst_ip), self._mac_str_to_int(dst_mac_str))
                print "IP to MAC: ", event.dst_ip, " - ", dst_mac_str
            else:
                print "warning: fail to get mac of: ", dst_ip_str

        self.bpf_lb["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_lb.kprobe_poll()

    def _get_servers_load(self):
        numServers = len(self.servers)
        server_frees = [0 for i in range(0, numServers)]
        for i in range(0, numServers):
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                    CommunityData('public', mpModel=0),
                    UdpTransportTarget((str(self.servers[i]), 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('.1.3.6.1.4.1.2021.10.1.3.1')) ) )

            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
                oid, val = varBinds[0]
                server_frees[i] = 10 - min(10, int(round(10*float(val))))
        return server_frees

    def _cal_server_weights(self, server_frees):
        server_weights = [0 for _ in range(0, len(self.server_weights))]
        for i in range(0, len(self.server_weights)):
            server_weights[i] = self.server_weights[i] * server_frees[i]
        return server_weights

    def _cal_server_map(self, server_weights):
        new_server_map = []
        sum_weight = sum(server_weights)
        for i in range(0, len(self.servers)):
            num_of_sched = max(1, int(server_weights[i] * self.HASHMAP_SIZE / sum_weight))
            new_server_map.extend([int(self.servers[i]) for _ in range(0, num_of_sched)])

        if len(new_server_map) < self.HASHMAP_SIZE:
            new_server_map.extend([self.server_ips[-1] for _ in range(len(new_server_map), self.HASHMAP_SIZE)])

        random.shuffle(new_server_map)
        return new_server_map
        # return random.shuffle(new_server_map)

    def update_server_map(self):
        server_frees = self._get_servers_load()
        server_weights = self._cal_server_weights(server_frees)
        new_server_map = self._cal_server_map(server_weights)

        for i in range(0, len(new_server_map)):
            k = self.tb_server_ips.Key(i)
            leaf = self.tb_server_ips.Leaf(new_server_map[i])
            # print "update mapping: ", i, ": ", new_server_map[i]
            self.tb_server_ips[k] = leaf
        self.new_server_map = new_server_map

        print "server_weights: ", server_weights


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--period", default=60, type=int, help="period to update server load in seconds")
    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("servers", nargs='+', type=unicode, help="servers to load balance")
    args = parser.parse_args()

    elb = ELB(args.iface, args.servers)

    elb.attach_iface()
    elb.open_events()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    # a separated thread to recaculate server distribution based on new server weights
    to_stop = threading.Event()

    def sleep_with_stopcheck(seconds):
        remain = seconds
        while not to_stop.is_set():
            time.sleep(1)
            remain = remain - 1
            if remain == 0:
                return

    def update_server_map():
        try:
            while not to_stop.is_set():
                elb.update_server_map()
                sleep_with_stopcheck(args.period)
        except Exception as e:
            print(e)

    server_map_updater = threading.Thread(target=update_server_map)
    server_map_updater.start()

    try:
        while True:
            elb.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        elb.detach_iface()
        to_stop.set()
        server_map_updater.join()
        print "Done"
