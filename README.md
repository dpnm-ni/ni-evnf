# eVNF

This repo contains example VNFs for the CNSM paper "Building Hybrid Virtual Network Functions with eXpress Data Path".

## Requirements

We tested eVNF in Ubuntu 16.04 with kernel v4.14, but any Ubuntu and kernel version with XDP support should work well. An XDP-supported NICs should be used, see [XDP supported drivers](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp). Generic NICs also can work, but expect degraded performance.

If you want to test service function chain with Openstack, use QEMU for the hypevisor and virtio for VM's NIC driver. Set VM's NIC to multiqueue and turn off guest csum. The number of queues should be x2 the number of vCPUs.

```xml
<driver queues='2'>
    <guest csum='off'/>
</driver>
```

## Installation

* Install [BCC](https://github.com/iovisor/bcc)
* Install required modules

    ```shell
    pip install -r requirements.txt
    ```

## Usage

Use `-h` option to see detail usage for each VNF

```shell
cd edpi
sudo python edpi.py -h
```

## License
Code under [edpi/nDPI](edpi/nDPI) uses [LGPLv3](https://choosealicense.com/licenses/lgpl-3.0/). Remaining code uses
[MIT](https://choosealicense.com/licenses/mit/).
