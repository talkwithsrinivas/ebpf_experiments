#!/usr/bin/python3
from bcc import BPF

program = r"""
int hello(void *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    pid = pid >> 32;
    char command[128];
    bpf_get_current_comm(&command, sizeof(command));
    if (pid%2 == 0) {
        bpf_trace_printk("Hello World Even!, pid = %u, comm=%s", pid, command);
    } else {
        bpf_trace_printk("Hello World Odd!, pid = %u, comm=%s", pid, command);
    }
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

b.trace_print()
