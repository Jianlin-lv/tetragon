// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_exit.h"
#include "bpf_tracing.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/*
 * Hooking on acct_process kernel function, which is called on the task's
 * exit path once the task is the last one in the group. It's stable since
 * v4.19, so it's safe to hook for us.
 *
 * It's initialized for thread leader:
 *
 *   clone {
 *     copy_process
 *       copy_signal
 *         atomic_set(&sig->live, 1);
 *   }
 *
 * Incremented for each new thread:
 *
 *   clone {
 *     copy_process
 *       atomic_inc(&current->signal->live);
 *     ...
 *     wake_up_new_task
 *   }
 *
 * Decremented for each exiting thread:
 *
 *   do_exit {
 *     group_dead = atomic_dec_and_test(&tsk->signal->live);
 *     ...
 *     if (group_dead)
 *              acct_process();
 *     ...
 *   }
 *
 * Hooking to acct_process we ensure tsk->signal->live is 0 and
 * we are the last one of the thread group.
 */
__attribute__((section("kprobe/disassociate_ctty"), used)) int
event_exit(struct pt_regs *ctx)
{
	int on_exit = (int)PT_REGS_PARM1_CORE(ctx);

	if (on_exit)
		event_exit_send(ctx, get_current_pid_tgid() >> 32);
	return 0;
}
