#define KBUILD_MODNAME "efw"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ETHTYPE_IP 0x0800

#define TCP_ALLOW 0x0001
#define TCP_BLOCK 0x0002

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
    u16 ip_proto;
} __attribute__((packed));

struct lpm_key_v4_t {
    u32 prefixlen;
    u8 data[4];
}  __attribute__((packed));

BPF_TABLE("hash", u32, u64, tb_ip_mac, 1024);
BPF_TABLE("array", int, u16, tb_tcp_dest_lookup, 65536);
BPF_LPM_TRIE(tb_subnet_allow, struct lpm_key_v4_t, u32, 128);
// BPF_LPM_TRIE(tb_subnet_block, u64, u32, 128);
BPF_DEVMAP(tb_devmap, 1);
BPF_PERF_OUTPUT(events);
BPF_PROG_ARRAY(tb_prog_array, 1);

int fw(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    u64 *dst_mac_p;

    /* parsing packet structure */

    struct eth_tp *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

    if (ntohs(eth->type) != ETHTYPE_IP)
        return XDP_PASS;

    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);
    u32 dst_ip = ntohl(ip->daddr);

    /* handle tcp */


    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        CURSOR_ADVANCE(tcp, cursor, sizeof(*tcp), data_end);

        /* lookup port */

        int tcp_dest = ntohs(tcp->dest);
        u16 *tcp_dest_lookup_p = tb_tcp_dest_lookup.lookup(&tcp_dest);
        if (tcp_dest_lookup_p) {
            if ((*tcp_dest_lookup_p) & TCP_ALLOW) {
                goto FORWARD;
            }
        }

        /* lookup source subnet */
        struct lpm_key_v4_t lpm_key_v4 = {};
        lpm_key_v4.prefixlen = 32;
        lpm_key_v4.data[0] = (dst_ip >> 24) & 0xff;
        lpm_key_v4.data[1] = (dst_ip >> 16) & 0xff;
        lpm_key_v4.data[2] = (dst_ip >> 8) & 0xff;
        lpm_key_v4.data[3] = dst_ip & 0xff;

        u32 *lpm_val_v4_p = tb_subnet_allow.lookup(&lpm_key_v4);
        if(lpm_val_v4_p) {
            goto FORWARD;
        }

        if (tcp_dest_lookup_p) {
            if ((*tcp_dest_lookup_p) & TCP_BLOCK) {
                return XDP_DROP;
            }
        }

        return XDP_PASS;

    } else { // todo: handle UDP
        return XDP_PASS;
    }

FORWARD:
    /* go to next XDP progs if exists */
    tb_prog_array.call(ctx, 0);

    if (dst_ip == LOCAL_IP)
        return XDP_PASS;

    /* Forwarding */
    dst_mac_p = tb_ip_mac.lookup(&dst_ip);
    if (!dst_mac_p) {
        events.perf_submit(ctx, &dst_ip, sizeof(dst_ip));
        return XDP_PASS;
    }

    eth->src = htonll(LOCAL_MAC);
    eth->dst = htonll(*dst_mac_p);

    return XDP_TX;
}
