// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

SEC("usdt/path/to/build/src/bitcoind:net:outbound_connection")
int BPF_USDT(usdt_auto_attach, u64 id, void *addr, void *type, u64 network, u64 existing_connections) {
	char address[5];
	bpf_probe_read_user_str(address, sizeof(address), addr);
	bpf_printk("outbound connection: id=%lx address5=%s", id, address);
	return 0;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";
