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
#define HASHMAP_SIZE _HASHMAP_SIZE

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
    u8 protocol;
}; __attribute__((packed));

// see: https://lkml.org/lkml/2003/9/17/24
// but fold the sum l two times

static inline u16 incr_checksum(u16 old_check, u16 old, u16 new){
    u32 sum;
    old_check = ~ntohs(old_check);
    old = ~old;
    sum = (u32)old_check + old + new;
    sum = (sum & 0xffff) + (sum >> 16);
    return htons(~( (u16)(sum >> 16) + (sum & 0xffff) ));
}

static inline u8 five_tuples_hash(struct flow_id_t *flow_id) {
    u32 tmp = (flow_id->src_ip * 59) ^ flow_id->dst_ip ^ \
        ((u32)(flow_id->src_port) << 16) ^ ((u32)(flow_id->dst_port)) ^ \
        ((u32)(flow_id->protocol));
    tmp = (tmp >> 24) + ((tmp >> 16) & 0xff) + ((tmp >> 8) & 0xff) + (tmp & 0xff);
    tmp = ((tmp >> 8) & 0xff) + (tmp & 0xff);
    return (u8) (((tmp >> 8) & 0xff) + (tmp & 0xff));

}

BPF_TABLE("hash", u32, u64, tb_ip_mac, 1024);
BPF_TABLE("array", int, u32, tb_server_ips, HASHMAP_SIZE);
// BPF_ARRAY(tb_server_ips, u32, HASHMAP_SIZE);
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



    if (ntohl(ip->daddr) == LOCAL_IP) {
        /* to server. get new sever address and reclacing dst ip */

        struct flow_id_t flow_id = {};
        flow_id.src_ip = ntohl(ip->saddr);
        flow_id.dst_ip = ntohl(ip->daddr);
        flow_id.src_port = ntohs(tcp->source);
        flow_id.dst_port = ntohs(tcp->dest);
        flow_id.protocol = ip->protocol;

        int new_server_idx = five_tuples_hash(&flow_id);
        u32 new_server_ip;
        u32 *new_server_ip_p = tb_server_ips.lookup(&new_server_idx);
        if(!new_server_ip_p)
            return XDP_PASS;

        ip_sub_old = ntohs(ip->daddr >> 16);
        ip->daddr = htonl(*new_server_ip_p);
        ip_sub_new = ntohs(ip->daddr >> 16);

        bpf_trace_printk("id: %u, server ip: %u\n", new_server_idx, *new_server_ip_p);

    } else {
        /* to client. replacing src ip */

        ip_sub_old = ntohs(ip->saddr >> 16);
        ip->saddr = htonl(LOCAL_IP);
        ip_sub_new = ntohs(ip->saddr >> 16);
    }



    /* recompute checksum */

    ip->check = incr_checksum(ip->check, ip_sub_old, ip_sub_new);
    tcp->check = incr_checksum(tcp->check, ip_sub_old, ip_sub_new);
    // ip->check = 0;
    // ip->check = checksum((u16 *)ip, sizeof(struct iphdr));

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
