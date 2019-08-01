// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "bpf_load.h"
#include "sock_example.h"
#include <unistd.h>
#include <arpa/inet.h>

int main(int ac, char **argv)
{
	char filename[256];
	FILE *f;
	int i, sock;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	sock = open_raw_sock("lo");

	assert(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, prog_fd,
			  sizeof(prog_fd[0])) == 0);

	f = popen("ping6 -c5 localhost", "r");
	(void) f;

	for (i = 0; i < 6; i++) {
		long long ip_cnt, ipv6_cnt;
		long long tcp_cnt, udp_cnt, icmp_cnt, icmpv6_cnt;
		int key;

		//add
		key = ETH_P_IP;
		assert(bpf_map_lookup_elem(map_fd[0], &key, &ip_cnt) == 0);

		key = ETH_P_IPV6;
		assert(bpf_map_lookup_elem(map_fd[0], &key, &ipv6_cnt) == 0);

		printf("IP %lld IPV6 %lld pakets\n",
		       ip_cnt, ipv6_cnt);
		
		//change map_fd[0] -> map_fd[1]
		//key = IPPROTO_TCP;
		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd[1], &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd[1], &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd[1], &key, &icmp_cnt) == 0);

		key = IPPROTO_ICMPV6;
		assert(bpf_map_lookup_elem(map_fd[1], &key, &icmpv6_cnt) == 0);
	
		printf("TCP %lld UDP %lld ICMP %lld ICMPV6 %lld pakets\n",
		       tcp_cnt, udp_cnt, icmp_cnt, icmpv6_cnt);
		sleep(1);
	}

	return 0;
}
