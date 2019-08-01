#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h> //add
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map_l3 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256 * 256,
};

struct bpf_map_def SEC("maps") my_map_l4 = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index_l3 = load_half(skb, offsetof(struct ethhdr, h_proto));
	int index_l4 = load_byte(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr));
	long *value_l3, *value_l4;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value_l3 = bpf_map_lookup_elem(&my_map_l3, &index_l3);
	if (value_l3)
		__sync_fetch_and_add(value_l3, 1);

	value_l4 = bpf_map_lookup_elem(&my_map_l4, &index_l4);
	if (value_l4)
		__sync_fetch_and_add(value_l4, 1);

	return 0;
}
char _license[] SEC("license") = "GPL";
