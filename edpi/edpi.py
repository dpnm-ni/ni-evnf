#!/usr/bin/python

import time
import sys
import os
import socket
import threading
import argparse
import ctypes as ct
from bcc import BPF

from common import helpers


class FLowId(ct.Structure):
    _fields_ = [('flags', ct.c_uint8),
                ('src_ip', ct.c_uint32),
                ('dst_ip', ct.c_uint32),
                ('src_port', ct.c_uint16),
                ('dst_port', ct.c_uint16),
                ('protocol', ct.c_uint8)]


class EDPI(object):
    """docstring for EDPI"""

    def __init__(self, iface, mode, bpf_src="edpi.c"):
        super(EDPI, self).__init__()

        self.iface = iface
        self.bpf_src = bpf_src
        self.mode = mode
        self.bpf = self._create_bpf()

        self.fn = self.bpf.load_func("dpi", BPF.XDP)

        self.tb_ip_mac = self.bpf.get_table("tb_ip_mac")
        self.tb_new_ip_events = self.bpf.get_table("tb_new_ip_events")

        self.tb_detected_flow = self.bpf.get_table("tb_detected_flow")

        self.SOCK_PATH = "/tmp/sock_edpi"
        self.DETECTED = self.tb_detected_flow.Leaf(1)
        self.d_flow = FLowId()
        self.conn = self.init_unix_sock(self.SOCK_PATH)

    def _create_bpf(self):
        ip_int = helpers.get_ip_int(self.iface)
        mac_int = helpers.get_mac_int(self.iface)

        cflags = ["-w",
                  "-D_LOCAL_IP=%s" % ip_int,
                  "-D_WORKING_MODE=%s" % self.mode,
                  "-D_LOCAL_MAC=%s" % mac_int]

        return BPF(src_file=self.bpf_src, debug=0, cflags=cflags)

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

    def attach_iface(self):
        self.bpf.attach_xdp(self.iface, self.fn, 0)

    def detach_iface(self):
        self.bpf.remove_xdp(self.iface, 0)

    def start_newip_hander_thread(self):
        helpers.setup_newip_handler(self.bpf,
                                    self.tb_ip_mac,
                                    self.tb_new_ip_events)

        event_poll_thread = threading.Thread(target=self._event_poll)
        event_poll_thread.daemon = True
        event_poll_thread.start()

    def _event_poll(self):
        try:
            while True:
                self.bpf.kprobe_poll()
        except Exception as e:
            print e
            pass

    def add_detected_flow(self):
        # install detected flow to table
        if (self.conn.recv_into(self.d_flow)):
            if (self.d_flow.flags == 1):
                key = self.tb_detected_flow.Key(self.d_flow.src_ip,
                                                self.d_flow.dst_ip,
                                                self.d_flow.src_port,
                                                self.d_flow.dst_port,
                                                self.d_flow.protocol)
                self.tb_detected_flow[key] = self.DETECTED

                print "new elephant flow: {}:{}->{}:{}".format(self.d_flow.src_ip,
                                                               self.d_flow.src_port,
                                                               self.d_flow.dst_ip,
                                                               self.d_flow.dst_port)

            elif (self.d_flow.flags == 0):
                key = self.tb_detected_flow.Key(self.d_flow.src_ip,
                                                self.d_flow.dst_ip,
                                                self.d_flow.src_port,
                                                self.d_flow.dst_port,
                                                self.d_flow.protocol)
                del self.tb_detected_flow[key]

                print "idle elephant flow: {}:{}->{}:{}".format(self.d_flow.src_ip,
                                                                self.d_flow.dst_ip,
                                                                self.d_flow.src_port,
                                                                self.d_flow.dst_port)
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
    edpi.start_newip_hander_thread()

    print "eBPF prog Loaded"
    sys.stdout.flush()

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
