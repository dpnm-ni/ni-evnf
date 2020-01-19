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

class FLowId(ct.Structure):
    _fields_ = [ ('flags',ct.c_uint8),
                ('src_ip',ct.c_uint32),
                ('dst_ip',ct.c_uint32),
                ('src_port', ct.c_uint16),
                ('dst_port', ct.c_uint16),
                ('protocol', ct.c_uint8)]

class EDPI(object):
    """docstring for EDPI"""
    def __init__(self, iface, mode, bpf_src="edpi.c"):
        super(EDPI, self).__init__()
        self.iface = iface

        _local_ip_str = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']
        self.LOCAL_IP = int(IPv4Address(_local_ip_str))

        _local_mac_str = get_mac_address(interface=iface)
        self.LOCAL_MAC = self.mac_str_to_int(_local_mac_str)

        self.bpf_dpi = BPF(src_file=bpf_src, debug=0,
            cflags=["-w",
                    "-D_LOCAL_IP=%s" % self.LOCAL_IP,
                    "-D_WORKING_MODE=%s" % mode,
                    "-D_LOCAL_MAC=%s" % self.LOCAL_MAC])

        self.fn_dpi = self.bpf_dpi.load_func("dpi", BPF.XDP)
        self.tb_ip_mac = self.bpf_dpi.get_table("tb_ip_mac")
        self.tb_detected_flow = self.bpf_dpi.get_table("tb_detected_flow")

        self.SOCK_PATH = "/tmp/sock_edpi"
        self.DETECTED = self.tb_detected_flow.Leaf(1)
        self.d_flow = FLowId()
        self.conn = self.init_unix_sock(self.SOCK_PATH)


    def init_unix_sock(self, sock_path):
        # unix socket to recv detected flow from nDPI
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.remove(sock_path)
        except OSError:
            pass
        sock.bind(sock_path)
        sock.listen(1)
        print "Trying to connect to nDPI engine..."
        conn, addr = sock.accept()
        print "Connected"
        return conn

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
        self.bpf_dpi.attach_xdp(self.iface, self.fn_dpi, 0)

    def detach_iface(self):
        self.bpf_dpi.remove_xdp(self.iface, 0)

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

        self.bpf_dpi["events"].open_perf_buffer(_process_event, page_cnt=512)

    def poll_events(self):
        self.bpf_dpi.kprobe_poll()

    def add_detected_flow(self):
        # install detected flow to table
        # cdef CyFlowID d_flow
        if (self.conn.recv_into(self.d_flow)):
            if (self.d_flow.flags == 1):
                key = self.tb_detected_flow.Key(self.d_flow.src_ip, self.d_flow.dst_ip,
                    self.d_flow.src_port, self.d_flow.dst_port, self.d_flow.protocol)
                self.tb_detected_flow[key] = self.DETECTED

                print "new elephant flow: ", self.d_flow.src_ip, self.d_flow.dst_ip, \
                    self.d_flow.src_port, self.d_flow.dst_port

            elif (self.d_flow.flags == 0):
                key = self.tb_detected_flow.Key(self.d_flow.src_ip, self.d_flow.dst_ip,
                    self.d_flow.src_port, self.d_flow.dst_port, self.d_flow.protocol)
                del self.tb_detected_flow[key]

                print "idle elephant flow: ", self.d_flow.src_ip, self.d_flow.dst_ip, \
                    self.d_flow.src_port, self.d_flow.dst_port
            else:
                 print "warning: unsupported flags: ", self.d_flow.flags

            # TODO: else: deleted flows

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("-m", "--mode", default=1, type=int, choices=[1, 2],
            help="working mode. 1 for inline, 2 for capture. Default is inline")

    args = parser.parse_args()

    edpi = EDPI(args.iface, args.mode)
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
        while True:
            edpi.add_detected_flow()
    except KeyboardInterrupt:
        pass

    finally:
        edpi.detach_iface()
        edpi.conn.close()
        print "Done"
