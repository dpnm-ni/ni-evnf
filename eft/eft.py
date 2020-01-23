#!/usr/bin/python

import threading
import time
import sys
import argparse

from bcc import BPF

from common import helpers


class EFT(object):
    """docstring for EFT"""

    def __init__(self, iface, bpf_src="eft.c"):
        super(EFT, self).__init__()

        self.iface = iface
        self.bpf_src = bpf_src
        self.bpf = self._create_bpf()

        self.bpf_fn = self.bpf.load_func("ft", BPF.XDP)

        self.tb_ip_mac = self.bpf.get_table("tb_ip_mac")
        self.tb_new_ip_events = self.bpf.get_table("tb_new_ip_events")
        self.tb_prog_array = self.bpf.get_table("tb_prog_array")

        self.tb_flow_stats = self.bpf.get_table("tb_flow_stats")

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

    def print_stats(self):
        message_arr = []
        message_arr.append("---------------------------------------------------")
        message_arr.append("proto, src_ip:port -> dst_ip:port  : packets, bytes")
        message_arr.append("---------------------------------------------------")

        for flow_id, flow_stat in self.tb_flow_stats.items():
            src_ip_str = helpers.int_to_ip_str(flow_id.src_ip)
            dst_ip_str = helpers.int_to_ip_str(flow_id.dst_ip)

            mess = "%d, %s:%d -> %s:%d \t: %d, %d" % (
                flow_id.ip_proto,
                src_ip_str,
                flow_id.src_port,
                dst_ip_str,
                flow_id.dst_port,
                flow_stat.pkt_cnt,
                flow_stat.byte_cnt
            )

            message_arr.append(mess)

        message_arr.append('\n')
        message = '\n'.join(mess for mess in message_arr)
        print message


def parse_cli_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("-t", "--timeout", default=60, type=int,
                        help="flow timeout in seconds")
    parser.add_argument("-i", "--interval", default=2, type=int,
                        help="update interval in seconds")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_cli_args()

    eft = EFT(args.iface)
    eft.attach_iface()

    eft.start_newip_hander_thread()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    try:
        while True:
            time.sleep(args.interval)
            eft.print_stats()

    except KeyboardInterrupt:
        pass

    finally:
        eft.detach_iface()
        print "Done"
