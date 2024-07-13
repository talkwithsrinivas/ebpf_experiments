#include <linux/bpf.h>
#include <linux/version.h> 
#include <bpf/bpf_helpers.h>

SEC ("tp/syscalls/sys_enter_execve")
int detect_execve()
{
    bpf_printk("%s\n","execve called");
    return 1;
}

char _license[] SEC("license") = "GPL";
int _version SEC ("version") = LINUX_VERSION_CODE;
