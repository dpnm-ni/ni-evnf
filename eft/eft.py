#!/usr/bin/python

import time
import sys
import argparse

from bcc import BPF

from common import helpers


def parse_cli_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("-t", "--timeout",
                        default=60, type=int,
                        help="flow timeout in seconds")
    parser.add_argument("-i", "--interval",
                        default=2, type=int,
                        help="update interval in seconds")

    return parser.parse_args()


def init_bpf(iface, bpf_src="eft.c"):
    ip_int = helpers.get_ip_int(iface)
    mac_int = helpers.get_mac_int(iface)
    cflags = ["-w",
              "-D_LOCAL_IP=%s" % ip_int,
              "-D_LOCAL_MAC=%s" % mac_int]

    bpf = BPF(src_file=bpf_src, debug=0, cflags=cflags)

    return bpf


def print_stats(tb_flow_stats):
    message_arr = []
    message_arr.append("---------------------------------------------------")
    message_arr.append("proto, src_ip:port -> dst_ip:port  : packets, bytes")
    message_arr.append("---------------------------------------------------")

    for flow_id, flow_stat in tb_flow_stats.items():
        src_ip_str = helpers.int_to_ip_str(flow_id.src_ip),
        dst_ip_str = helpers.int_to_ip_str(flow_id.dst_ip),

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

    message.append('\n')
    message = '\n'.join(mess for mess in message_arr)
    print message


if __name__ == "__main__":

    args = parse_cli_args()
    iface = args.iface

    bpf = init_bpf(iface)
    bpf_fn = bpf.load_func("ft", BPF.XDP)
    helpers.attach_iface(bpf, iface, bpf_fn)

    newip_handler_thread = helpers.new_ip_handler_thread(bpf)
    newip_handler_thread.start()

    print "eBPF prog Loaded"
    sys.stdout.flush()

    tb_flow_stats = bpf.get_table("tb_flow_stats")
    try:
        while True:
            time.sleep(args.interval)
            print_stats(tb_flow_stats)

    except KeyboardInterrupt:
        pass

    finally:
        helpers.detach_iface(bpf, iface)
        print "Done"
