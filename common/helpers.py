#!/usr/bin/python

import threading
import socket
import struct

import ctypes as ct
import netifaces as ni

from bcc import BPF
from getmac import get_mac_address


def get_ip_int(iface):
    ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
    ip_int = ip_str_to_int(ip_str)
    return ip_int


def get_mac_int(iface):
    mac_str = get_mac_address(interface=iface)
    mac_int = mac_str_to_int(mac_str)
    return mac_int


def ip_str_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip_str(addr):
    ip_str = socket.inet_ntoa(struct.pack("!I", addr))
    return ip_str


def mac_str_to_int(mac):
    mac_arr = mac.split(':')
    tmp = ""
    for i in range(0, 6):
        tmp += mac_arr[i]
    return int(tmp, 16)


def set_next_vnf(tb_prog_array, fd):
    tb_prog_array[ct.c_int(0)] = ct.c_int(fd)


def clear_next_vnf(tb_prog_array):
    tb_prog_array[ct.c_int(0)]


def attach_iface(bpf_obj, iface, fn):
    bpf_obj.attach_xdp(iface, fn, 0)


def detach_iface(bpf_obj, iface):
    bpf_obj.remove_xdp(iface, 0)


def setup_newip_handler(bpf_obj, tb_ip_mac, tb_new_ip_events):
    def _process_event(ctx, data, size):
        class Event(ct.Structure):
            _fields_ = [("dst_ip", ct.c_uint32)]

        event = ct.cast(data, ct.POINTER(Event)).contents
        dst_ip_str = int_to_ip_str(event.dst_ip)
        dst_mac_str = get_mac_address(ip=dst_ip_str)

        if dst_mac_str is not None:
            _set_tb_ip_mac(tb_ip_mac,
                           int(event.dst_ip),
                           mac_str_to_int(dst_mac_str))
            print "IP to MAC: ", dst_ip_str, " - ", dst_mac_str
        else:
            print "warning: fail to get mac of: ", dst_ip_str

    tb_new_ip_events.open_perf_buffer(_process_event, page_cnt=512)


def _set_tb_ip_mac(tb_ip_mac, ip, mac):
    k = tb_ip_mac.Key(ip)
    leaf = tb_ip_mac.Leaf(mac)
    tb_ip_mac[k] = leaf
