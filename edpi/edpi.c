#define KBUILD_MODNAME "efw"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ETHTYPE_IP 0x0800

// get from cflags
// detail: https://stackoverflow.com/questions/25254043/is-it-
// possible-to-compare-ifdef-values-for-conditional-use
#define NIC_MAC _NIC_MAC
#define NIC_IP _NIC_IP
#define IS_AF_XDP _IS_AF_XDP
#define IS_INLINE _IS_INLINE

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
    u8 ip_proto;
}; __attribute__((packed));

BPF_TABLE("hash", u32, u64, tb_ip_mac, 1024);
BPF_TABLE("hash", struct flow_id_t, u16, tb_detected_flow, 200000);
BPF_TABLE("array", int, int, qidconf_map, 64);
BPF_XSKMAP(xsks_map, 64);
BPF_PERF_OUTPUT(tb_new_ip_events);

int dpi(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;
    int index = ctx->rx_queue_index;

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

    if (ntohs(eth->type) != ETHTYPE_IP)
        return XDP_PASS;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    u32 dst_ip = ntohl(ip->daddr);
    if (dst_ip == NIC_IP)
        return XDP_PASS;

#if IS_INLINE
    u64 dst_mac = 0;
    u64 *dst_mac_p = tb_ip_mac.lookup(&dst_ip);
    if (!dst_mac_p) {
        tb_new_ip_events.perf_submit(ctx, &dst_ip, sizeof(dst_ip));
        return XDP_PASS;
    }
#endif

    /* extract 5 tuples. intentionally use network byte order */

    struct flow_id_t flow_id = {};
    flow_id.ip_proto = ip->protocol;
    flow_id.src_ip = ip->saddr;
    flow_id.dst_ip = ip->daddr;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);
        flow_id.src_port = udp->source;
        flow_id.dst_port = udp->dest;

    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);
        flow_id.src_port = tcp->source;
        flow_id.dst_port = tcp->dest;
    }

    /* let ndpi classify un-detected flows */
    if (!tb_detected_flow.lookup(&flow_id)) {
        /* bi-directional flow checking */
        u32 tmp;
        tmp = flow_id.src_port;
        flow_id.src_port = flow_id.dst_port;
        flow_id.dst_port = tmp;
        tmp = flow_id.src_ip;
        flow_id.src_ip = flow_id.dst_ip;
        flow_id.dst_ip = tmp;

#if IS_AF_XDP
        /* the default value in xsks_map should populated by AF_XDP kernel code */
        if (!tb_detected_flow.lookup(&flow_id) && xsks_map.lookup(&index)) {
                bpf_trace_printk("redirect to idx: %d\n", index);
                return xsks_map.redirect_map(index, 0);
            }

            bpf_trace_printk("dropped. idx is: %d\n", index);
            return XDP_DROP;

#else /* use normal kernel stack */
        if (!tb_detected_flow.lookup(&flow_id))
            return XDP_PASS;
#endif

    }

#if IS_INLINE
    /* forward detected flow */
    eth->src = htonll(NIC_MAC);
    eth->dst = htonll(*dst_mac_p);
    return XDP_TX;
#else /* use capture mode */
    return XDP_DROP;
#endif

}
