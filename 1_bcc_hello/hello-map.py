#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
#include<uapi/linux/ptrace.h>
BPF_HASH(uid_counter_table);
BPF_HASH(syscall_counter_table);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    u64 opcode = ctx->args[1];

    //only trace openat, write, execv
    if (opcode != 1 && opcode != 59 && opcode != 257) {
        bpf_trace_printk("Ignoring syscall id = : %d", opcode);
        return 0;
    }
    bpf_trace_printk("syscall id = : %d", opcode);
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = uid_counter_table.lookup(&uid);
    if (p != 0) {
       counter = *p;
    }
    counter++;
    uid_counter_table.update(&uid, &counter);

    counter = 0;
    p = syscall_counter_table.lookup(&opcode);
    if (p != 0) {
       counter = *p;
    }
    counter++;
    syscall_counter_table.update(&opcode, &counter);

    return 0;
}
"""

b = BPF(text=program)
#syscall_execve = b.get_syscall_fnname("execve")
#syscall_openat = b.get_syscall_fnname("openat")
#syscall_write = b.get_syscall_fnname("write")
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")
#b.attach_kprobe(event=syscall_execve, fn_name="hello")
#b.attach_kprobe(event=syscall_openat, fn_name="hello")
#b.attach_kprobe(event=syscall_write, fn_name="hello")

# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    s1 = ""
    #for k,v in b["uid_counter_table"].items():
    #    s += f"==== ID Table ==== {k.value}: {v.value}\t"
    #print(s)
    for k,v in b["syscall_counter_table"].items():
        s1 += f"==== syscall counter Table ==== {k.value}: {v.value}\t"
    s1 +=f"\n"
    print(s1)
