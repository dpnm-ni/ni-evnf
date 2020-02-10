#!/usr/bin/python

import threading
import time
import sys
import argparse
import multiprocessing

from bcc import BPF

from common import helpers


class EFT(object):
    """docstring for EFT"""

    def __init__(self, iface, is_inline, bpf_src="eft.c"):
        super(EFT, self).__init__()
        self.is_inline = is_inline

        self.iface = iface
        self.bpf_src = bpf_src
        self.bpf = self._create_bpf()

        self.cpu_range = range(0, multiprocessing.cpu_count())

        self.bpf_fn = self.bpf.load_func("ft", BPF.XDP)

        self.tb_ip_mac = self.bpf.get_table("tb_ip_mac")
        self.tb_new_ip_events = self.bpf.get_table("tb_new_ip_events")
        self.tb_prog_array = self.bpf.get_table("tb_prog_array")

        self.tb_flow_stats = self.bpf.get_table("tb_flow_stats")

    def _create_bpf(self):
        ip_int = helpers.get_ip_int(self.iface)
        mac_int = helpers.get_mac_int(self.iface)

        cflags = ["-w",
                  "-D_NIC_IP=%s" % ip_int,
                  "-D_NIC_MAC=%s" % mac_int,
                  "-D_IS_INLINE=%d" % (1 if self.is_inline is True else 0)]

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

    def start_print_stats_thread(self, interval):

        print_stats_thread = threading.Thread(target=self._print_stats_poll, args=[interval,])
        print_stats_thread.daemon = True
        print_stats_thread.start()

    def _print_stats_poll(self, interval):
        try:
            while True:
                time.sleep(interval)
                self._print_stats()
        except Exception as e:
            print e
            pass

    def _print_stats(self):
        message_arr = []
        message_arr.append("---------------------------------------------------")
        message_arr.append("proto, src_ip:port -> dst_ip:port  : packets, bytes")
        message_arr.append("---------------------------------------------------")

        for flow_id, flow_stat in self.tb_flow_stats.items():
            src_ip_str = helpers.int_to_ip_str(flow_id.src_ip)
            dst_ip_str = helpers.int_to_ip_str(flow_id.dst_ip)

            flow_stat_summary = self._sum_flow_stat(flow_stat)
            mess = "%d, %s:%d -> %s:%d \t: %d, %d" % (
                flow_id.ip_proto,
                src_ip_str,
                flow_id.src_port,
                dst_ip_str,
                flow_id.dst_port,
                flow_stat_summary[0],
                flow_stat_summary[1]
            )

            message_arr.append(mess)

        message_arr.append('\n')
        message = '\n'.join(mess for mess in message_arr)
        print message

    def _sum_flow_stat(self, flow_stat):
        pkt_cnt = sum([flow_stat[i].pkt_cnt for i in self.cpu_range])
        byte_cnt = sum([flow_stat[i].byte_cnt for i in self.cpu_range])
        return (pkt_cnt, byte_cnt)



def parse_cli_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("-t", "--timeout", default=60, type=int,
                        help="flow timeout in seconds")
    parser.add_argument("-I", "--interval", default=2, type=int,
                        help="update interval in seconds")
    parser.add_argument("-T", "--time", default=0, type=int,
                        help="total running time in seconds. default set to forever")
    parser.add_argument("-i", "--inline", dest='is_inline', default=False, action='store_true',
                        help="set working mode to inline. Default mode is capture")

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_cli_args()

    eft = EFT(args.iface, args.is_inline)
    eft.attach_iface()

    eft.start_newip_hander_thread()
    eft.start_print_stats_thread(args.interval)

    print "eBPF prog Loaded"
    sys.stdout.flush()

    try:
        if args.time == 0:
            while True:
                time.sleep(1)
        else:
            time.sleep(args.time)

    except KeyboardInterrupt:
        pass

    finally:
        eft.detach_iface()
        print "Done"

