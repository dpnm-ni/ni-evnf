import sys
sys.path.append("../")

from efw.efw import EFW
from elb.elb import ELB


iface = "ens4"
s_ips_str = [u"192.168.4.15", u"192.168.4.1"]

efw = EFW(iface, "../efw/efw.c")
elb = ELB(iface, s_ips_str, "../elb/elb.c")

s_frees = elb.get_servers_load()
print "s_frees: ", s_frees
s_weights_w_load = elb.cal_s_weights_w_load(s_frees)
print "s_weights_w_load: ", s_weights_w_load
new_s_hashmap = elb.cal_s_hashmap(s_weights_w_load)
print "new_s_hashmap: ", new_s_hashmap
elb.update_s_hashmap(new_s_hashmap)

efw.attach_iface()
efw.set_next_vnf(elb.fn_lb.fd)


efw.add_port(80, "allow")
efw.add_allow_subnet((24, (192, 168, 4, 0)), 1)
# k = efw.tb_subnet_allow.Key(24, (192, 168, 4, 4))
# print "val: ", efw.tb_subnet_allow[k]

elb.open_events()

print "eBPF prog Loaded"
sys.stdout.flush()

try:
    while 1:
        elb.poll_events()

except KeyboardInterrupt:
    pass

finally:
    efw.detach_iface()
    print "Done"
