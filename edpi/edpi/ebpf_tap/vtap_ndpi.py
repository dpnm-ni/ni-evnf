#!/usr/bin/env python

from bcc import BPF
from pyroute2 import IPRoute
import socket,os
import ctypes as ct

class FourTuplesFlow(ct.Structure):
     _fields_ = [ ('flags',ct.c_uint32),
                 ('src_ip',ct.c_uint32),
                 ('dst_ip',ct.c_uint32),
                 ('src_port', ct.c_uint16),
                 ('dst_port', ct.c_uint16)]

ifaceM = "veth0"
ifaceT = "tap0"
ipr = IPRoute()
SOCK_PATH = "/tmp/vtap_socket"
DETECTED = 1

# unix socket to recv detected flow from nDPI
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.remove(SOCK_PATH)
except OSError:
    pass
sock.bind(SOCK_PATH)
sock.listen(1)
conn, addr = sock.accept()
print "accept connection..."

# load the eBPF function
b = BPF(src_file="vtap_ndpi.c", debug=0)
fn = b.load_func("filter", BPF.SCHED_CLS)
print ifaceT, ": ", ipr.link_lookup(ifname=ifaceT)[0]

# attach eBPF program to ingress and egress
idx = ipr.link_lookup(ifname=ifaceM)[0]
ipr.tc("add", "clsact", idx)
ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
      parent="ffff:fff2", classid=1, direct_action=True)
ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
      parent="ffff:fff3", classid=1, direct_action=True)

# Recv detected flow info
tb_d_flow = b.get_table("tb_detected_flow")
# tb_count = b.get_table("tb_count")

d_flow = FourTuplesFlow()

try:
    print("Press Ctrl-C to terminate...")
    while True:
        read_bytes = conn.recv_into(d_flow)
        if (read_bytes):
            # for field in d_flow._fields_:
            #     print field[0], getattr(d_flow, field[0])
            
            # install detected flow to table
            if (d_flow.flags == 1):
                key = tb_d_flow.Key(d_flow.src_ip, d_flow.dst_ip, d_flow.src_port, d_flow.dst_port)
                val = tb_d_flow.Leaf(DETECTED)
                tb_d_flow[key] = val
                key = tb_d_flow.Key(d_flow.dst_ip, d_flow.src_ip, d_flow.dst_port, d_flow.src_port)
                val = tb_d_flow.Leaf(DETECTED)
                tb_d_flow[key] = val
                # TODO: else: deleted flows

except KeyboardInterrupt:
    conn.close()
    pass

finally:
    ipr.tc("del", "clsact", idx)
    # print "tb_d_flow: ", len(tb_d_flow.items())
    # print "tb_count: ", tb_count.items()
    print "--------exit--------"
