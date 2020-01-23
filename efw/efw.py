#!/usr/bin/python

import threading
import time
import sys
import argparse

from bcc import BPF

from common import helpers


class EFW(object):
    """docstring for EFW"""

    def __init__(self, iface, bpf_src="efw.c"):
        super(EFW, self).__init__()

        self.iface = iface
        self.bpf_src = bpf_src
        self.bpf = self._create_bpf()

        self.bpf_fn = self.bpf.load_func("fw", BPF.XDP)

        self.tb_ip_mac = self.bpf.get_table("tb_ip_mac")
        self.tb_prog_array = self.bpf.get_table("tb_prog_array")
        self.tb_new_ip_events = self.bpf.get_table("tb_new_ip_events")

        self.tb_subnet_allow = self.bpf.get_table("tb_subnet_allow")
        self.tb_tcp_dest_lookup = self.bpf.get_table("tb_tcp_dest_lookup")

    def _create_bpf(self):
        ip_int = helpers.get_ip_int(self.iface)
        mac_int = helpers.get_mac_int(self.iface)

        cflags = ["-w",
                  "-D_LOCAL_IP=%s" % ip_int,
                  "-D_LOCAL_MAC=%s" % mac_int]

        return BPF(src_file=self.bpf_src, debug=0, cflags=cflags)

    def set_next_vnf(self, fd):
        self.tb_prog_array[ct.c_int(0)] = ct.c_int(fd)

    def clear_next_vnf(self):
        del self.tb_prog_array[ct.c_int(0)]

    def attach_iface(self):
        self.bpf.attach_xdp(self.iface, self.bpf_fn, 0)

    def detach_iface(self):
        self.bpf.remove_xdp(self.iface, 0)

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("iface", help="iface to listen")
    args = parser.parse_args()

    efw = EFW(args.iface)
    efw.attach_iface()
    efw.start_newip_hander_thread()

    efw.add_port(80, "allow")
    efw.add_allow_subnet((24, (10, 10, 20, 0)))
    # k = efw.tb_subnet_allow.Key(24, (192, 168, 4, 4))

    print "eBPF prog Loaded"
    sys.stdout.flush()

    try:
        while 1:
            time.sleep(1)

    except KeyboardInterrupt:
        pass

    finally:
        efw.detach_iface()
        print "Done"
