#define KBUILD_MODNAME "eft"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ETHTYPE_IP 0x0800
#define MAC_HDR_LEN 14

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

struct ports_t {
    u16 src;
    u16 dst;
} __attribute__((packed));

struct flow_id_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 ip_proto;
} __attribute__((packed));

struct flow_stat_t {
    u64 pkt_cnt;
    u64 byte_cnt;
} __attribute__((packed));

BPF_TABLE("hash", struct flow_id_t, struct flow_stat_t, tb_flow_stats, 10240);
BPF_TABLE("hash", u32, u64, tb_ip_mac, 1024);
BPF_PERF_OUTPUT(events);
BPF_PROG_ARRAY(tb_prog_array, 1);

int ft(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    u64 *dst_mac_p;

    struct flow_id_t flow_id = {};
    struct flow_stat_t flow_stat = {};

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);
    if (ntohs(eth->type) != ETHTYPE_IP)
        return XDP_PASS;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);
    flow_id.src_ip = ntohl(ip->saddr);
    flow_id.dst_ip = ntohl(ip->daddr);
    flow_id.ip_proto = ip->protocol;
    u32 dst_ip = ntohl(ip->daddr);

    /* only need port info, which is same for both tcp & udp */
    struct ports_t *ports;
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        CURSOR_ADVANCE(ports, cursor, sizeof(*ports), data_end);
        flow_id.src_port = ports->src;
        flow_id.dst_port = ports->dst;
    }

    struct flow_stat_t flow_stat_zero = {};
    struct flow_stat_t *flow_stat_p = tb_flow_stats.lookup_or_init(&flow_id, &flow_stat_zero);
    if (flow_stat_p) {
        flow_stat_p->pkt_cnt += 1;
        flow_stat_p->byte_cnt += MAC_HDR_LEN + ntohs(ip->tot_len);
    }

FORWARD:
    /* go to next XDP progs if exists */
    tb_prog_array.call(ctx, 0);

    dst_mac_p = tb_ip_mac.lookup(&dst_ip);
    if (!dst_mac_p) {
        events.perf_submit(ctx, &dst_ip, sizeof(dst_ip));
        return XDP_PASS;
    }

    eth->src = htonll(LOCAL_MAC);
    eth->dst = htonll(*dst_mac_p);

    return XDP_TX;
}
