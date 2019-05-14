#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// #define IPPROTO_TCP 6
// #define IPPROTO_UDP 17
#define ETHPROTO_IP 0x0800

struct four_tuples_t {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
};

BPF_TABLE("hash", struct four_tuples_t, u16, tb_detected_flow, 40960);
// BPF_TABLE("hash", int, int, tb_count, 1024);

int filter(struct __sk_buff *skb) {

  u8 *cursor = 0;

  // int *p_pass, *p_clone;
  // int key;
  // int zero32 = 0;

  // key = 0;
  // p_clone = tb_count.lookup_or_init(&key, &zero32);
  // key = 1;
  // p_pass = tb_count.lookup_or_init(&key, &zero32);

  // parsing packet structure
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if (ethernet->type != ETHPROTO_IP) {
    goto PASS;
  }


  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  if (ip->nextp == IPPROTO_TCP) {
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
    
    struct four_tuples_t flow = {};
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    if (tb_detected_flow.lookup(&flow)) {
      goto PASS;
    }

    // struct four_tuples_t flow2 = {};
    // flow2.src_ip = ip->dst;
    // flow2.dst_ip = ip->src;
    // flow2.src_port = tcp->dst_port;
    // flow2.dst_port = tcp->src_port;

    // if (tb_detected_flow.lookup(&flow2)) {
    //   goto PASS;
    // }

  } else if (ip->nextp ==  IPPROTO_UDP) {
    // temporary
    goto PASS;

    struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

    struct four_tuples_t flow = {};
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = udp->sport;
    flow.dst_port = udp->dport;

  } else {
    goto PASS;
  }

  // (*p_clone)++;

  // tap0 egress
  bpf_clone_redirect(skb, 11, 1); 

  PASS:

  // (*p_pass)++;

  // return value: 0: bypass, 1: do action in the filter in load_balancer.py
  return 0;
}