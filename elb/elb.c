#define KBUILD_MODNAME "efw"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ETHTYPE_IP 0x0800
#define HTTPTYPE_TCP 80

// get from cflags
// detail: https://stackoverflow.com/questions/25254043/is-it-
// possible-to-compare-ifdef-values-for-conditional-use
#define LOCAL_MAC _LOCAL_MAC
#define LOCAL_IP _LOCAL_IP

#define htonll(_num) (__builtin_bswap64(_num) >> 16)

#define CURSOR_ADVANCE(_target, _cursor, _len,_data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(_cursor > _data_end) return XDP_DROP; })

struct eth_tp {
    u64 dst:48;
    u64 src:48;
    u16 type;
} __attribute__((packed));

struct flow_id_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
}; __attribute__((packed));

// static inline u16 checksum(u16 *buf, int bufsz) {
//     u32 sum = 0;

//     while (bufsz > 1) {
//         sum += *buf;
//         buf++;
//         bufsz -= 2;
//     }

//     if (bufsz == 1) {
//         sum += *(u8 *)buf;
//     }

//     sum = (sum & 0xffff) + (sum >> 16);
//     sum = (sum & 0xffff) + (sum >> 16);

//     return ~sum;
// }

BPF_TABLE("hash",u32, u64, tb_ip_mac, 1024);
BPF_PERF_OUTPUT(events);

int lb(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    u32 sum;
    u16 ip_sub_old;
    u16 ip_sub_new;

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    
    if (ntohs(eth->type) != ETHTYPE_IP)
        return XDP_PASS;
    
    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);


    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp;
    CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
    if(ntohs(tcp->dest) != HTTPTYPE_TCP && ntohs(tcp->source) != HTTPTYPE_TCP)
        return XDP_PASS;

    struct flow_id_t flow_id = {};
    flow_id.src_ip = ntohl(ip->saddr);
    flow_id.dst_ip = ntohl(ip->daddr);
    flow_id.src_port = ntohs(tcp->source);
    flow_id.dst_port = ntohs(tcp->dest);


    /* new ip */

    if (ntohl(ip->daddr) == LOCAL_IP) {
        // to server
        ip_sub_old = ntohs(ip->daddr >> 16);
        ip->daddr = htonl(3232236552); // 192.168.4.8
        ip_sub_new = ntohs(ip->daddr >> 16);
    } else {
        // to client
        ip_sub_old = ntohs(ip->saddr >> 16);
        ip->saddr = htonl(LOCAL_IP);
        ip_sub_new = ntohs(ip->saddr >> 16);
    }



    /* recompute checksum */

    // ip checksum
    u32 sum_new = ntohs(ip->check) + ip_sub_old + ~ip_sub_new;
    sum_new = (sum_new & 0xffff) + (sum_new >> 16);
    ip->check = htons((sum_new & 0xffff) + (sum_new >> 16) + 1);

    // ip->check = 0;
    // u16 sum_correct = checksum((u16 *)ip, sizeof(struct iphdr));
    // if (sum_new - sum_correct != 0)
    //     bpf_trace_printk("sum new: %u, correct: %u, proto %d\n",
    //         sum_new, sum_correct, ip->protocol);

    // tcpchecksum
    sum_new = ntohs(tcp->check) + ip_sub_old + ~ip_sub_new;
    sum_new = (sum_new & 0xffff) + (sum_new >> 16);
    tcp->check = htons((sum_new & 0xffff) + (sum_new >> 16) + 1);

    /* Forwarding */

    u64 dst_mac = 0;
    u32 dst_ip = ntohl(ip->daddr);
    u64 *dst_mac_p = tb_ip_mac.lookup(&dst_ip);
    if (!dst_mac_p) {
        events.perf_submit(ctx, &dst_ip, sizeof(dst_ip));
        return XDP_PASS;
    }

    eth->src = htonll(LOCAL_MAC);
    eth->dst = htonll(*dst_mac_p);

    return XDP_TX;
}
