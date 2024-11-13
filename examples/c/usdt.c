// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <linux/limits.h>
#include "usdt.skel.h"

static volatile sig_atomic_t exiting;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct usdt_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	skel = usdt_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = usdt_bpf__load(skel);
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	/*
	 * Auto attach by libbpf, libbpf should be able to find libc.so in your system.
	 * By default, auto attach does NOT specify pid, so we do pid filtering in BPF program
	 */
	err = usdt_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while (!exiting) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	usdt_bpf__destroy(skel);
	return -err;
}
