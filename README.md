# eVNF

This repo contains example VNFs for the bellow publications:
- N. V. Tu, J. Yoo and J. W. Hong, "Building Hybrid Virtual Network Functions with eXpress Data Path," *15th International Conference on Network and Service Management (CNSM)*, 2019
- N. V. Tu, J. Yoo and J. W. Hong, "Accelerating Virtual Network Functions with Fast-Slow Path Architecture using eXpress Data Path," *IEEE Transactions on Network and Service Management (TNSM)*, 2020

## Requirements

We tested eVNF in Ubuntu 16.04 and 19.10, with kernel v4.14 and v5.4, respectively, but any Ubuntu and kernel version with XDP support (and AF_XDP support, if AF_XDP is used) should work well. An XDP-supported NICs should be used, see [XDP supported drivers](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp). Generic NICs also can work, but expect degraded performance.

If you want to test service function chain with Openstack, use QEMU for the hypevisor and virtio for VM's NIC driver. Set VM's NIC to multiqueue and turn off guest csum. The number of queues should be x2 the number of vCPUs.

```xml
<driver queues='2'>
    <guest csum='off'/>
</driver>
```

## Installation

- Install [BCC](https://github.com/iovisor/bcc).
- Install required modules as superuser

    ```shell
    sudo pip install -r requirements.txt
    ```

## Configuration
- `elb` use direct routing, thus the web server need to support direct routing.
- `edpi` requires compilation and `pf_ring` kernel module. More details at [PF_RING AF_XDP](https://www.ntop.org/guides/pf_ring/modules/af_xdp.html)
    ```bash
    cd edpi
    ./make_pf_ring.sh
    cd PF_RING/kernel
    sudo insmod pf_ring.ko min_num_slots=65536 enable_tx_capture=0
    cd ../..
    ./make_edpi.sh
    ```

## Usage

Use `-h` option to see detailed usage for each VNF. For `edpi`, you need to manually run nDPI engine in another terminal after `edpi` is started.

```shell
sudo python -m edpi.edpi -h
```

## License
Code under [edpi/nDPI](edpi/nDPI) uses [LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/). Remaining code uses
[MIT](https://choosealicense.com/licenses/mit/).
