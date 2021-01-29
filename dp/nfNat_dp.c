#include <string.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/tcp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define MAX_SEGMENTS 8
#define DNAT_RULE_SIZE 64
#define SID_CONFIG_SIZE 16
#define assert_len(target, end)   \
  if ((void *)(target + 1) > end) \
    return XDP_DROP;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct sid_config_key
{
  __u8 sid[16];
};

struct sid_config_value
{
  __u8 flags;
};

struct dnat_rules_key
{
  __be32 dst;
  __be16 dport;
};

struct dnat_rules_value
{
  __be32 dst;
  __be16 dport;
};

struct bpf_map_def SEC("maps") sid_configs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct sid_config_key),
    .value_size = sizeof(struct sid_config_value),
    .max_entries = SID_CONFIG_SIZE,
};

struct bpf_map_def SEC("maps") dnat_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct dnat_rules_key),
    .value_size = sizeof(struct dnat_rules_value),
    .max_entries = DNAT_RULE_SIZE,
};

__attribute__((__always_inline__)) static inline int nat(struct xdp_md *ctx, void *nxt_ptr, struct in6_addr *segments)
{
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *ipv4 = (struct iphdr *)nxt_ptr;
  struct sid_config_value *config;

  assert_len(ipv4, data_end);

  struct tcphdr *tcp = (struct tcphdr *)(ipv4 + 1);
  assert_len(tcp, data_end);

  config = bpf_map_lookup_elem(&sid_configs, segments);
  if (!config)
    return XDP_DROP;

  if (config->flags & 0x01)
  {
    // enable dnat
    struct dnat_rules_key key = {};
    struct dnat_rules_value *rule;
    key.dst = ipv4->daddr;
    key.dport = tcp->dest;
    rule = bpf_map_lookup_elem(&dnat_rules, &key);
    if (rule)
    {
      ipv4->daddr = rule->dst;
      tcp->dest = rule->dport;
    }
  }
  if (config->flags & 0x02)
  {
    // enable masquerade
  }

  return XDP_PASS;
}

__attribute__((__always_inline__)) static inline int process_srv6hdr(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth, struct ipv6hdr *ipv6)
{
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6_sr_hdr *srv6 = (struct ipv6_sr_hdr *)nxt_ptr;
  int ret;
  assert_len(srv6, data_end);

  if (srv6->nexthdr != IPPROTO_IPIP)
    return XDP_PASS;
  if (srv6->segments_left > srv6->first_segment)
    return XDP_DROP;

  struct in6_addr *segments = (struct in6_addr *)((void *)srv6 + 8);

  assert_len(segments + srv6->first_segment + 1, data_end);
  assert_len(segments + srv6->segments_left, data_end);
  ret = nat(ctx, segments + srv6->first_segment + 1, segments + srv6->segments_left);
  srv6->segments_left++;
  return ret;
}

__attribute__((__always_inline__)) static inline int process_ipv6hdr(struct xdp_md *ctx, void *nxt_ptr, struct ethhdr *eth)
{
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *ipv6 = (struct ipv6hdr *)nxt_ptr;

  assert_len(ipv6, data_end);

  if (ipv6->nexthdr != IPPROTO_ROUTING)
    return XDP_PASS;

  return process_srv6hdr(ctx, ipv6 + 1, eth, ipv6);
}

__attribute__((__always_inline__)) static inline int process_ethhdr(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = (struct ethhdr *)data;

  assert_len(eth, data_end);

  if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
    return XDP_PASS;

  return process_ipv6hdr(ctx, eth + 1, eth);
}

SEC("xdp")
int process_rx(struct xdp_md *ctx)
{
  return process_ethhdr(ctx);
}

char _license[] SEC("license") = "GPL";
