#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define assert_len(target, end)   \
  if ((void *)(target + 1) > end) \
    return XDP_DROP;

static inline int process_ethhdr(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = (struct ethhdr *)data;

  assert_len(eth, data_end);

  return XDP_PASS;
}

SEC("xdp")
int process_rx(struct xdp_md *ctx)
{
  return process_ethhdr(ctx);
}

char _license[] SEC("license") = "GPL";
