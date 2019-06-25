import argparse
import threading
import time

import sys
sys.path.append("../")
from efw.efw import EFW
from elb.elb import ELB

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--period", default=60, type=int, help="period to update server load in seconds")
    parser.add_argument("iface", help="iface to listen")
    parser.add_argument("servers", nargs='+', type=unicode, help="servers to load balance")
    args = parser.parse_args()

    efw = EFW(args.iface, "../efw/efw.c")
    elb = ELB(args.iface, args.servers, "../elb/elb.c")


    efw.attach_iface()
    efw.set_next_vnf(elb.fn_lb.fd)


    efw.add_port(80, "allow")
    efw.add_allow_subnet((24, (192, 168, 4, 0)), 1)
    # k = efw.tb_subnet_allow.Key(24, (192, 168, 4, 4))
    # print "val: ", efw.tb_subnet_allow[k]

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

    update_server_map_thread = threading.Thread(target=update_server_map)
    update_server_map_thread.start()

    try:
        while True:
            elb.poll_events()

    except KeyboardInterrupt:
        pass

    finally:
        efw.detach_iface()
        to_stop.set()
        update_server_map_thread.join()
        print "Done"
