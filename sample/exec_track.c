#include<linux/bpf.h> 
#include<bpf/libbpf.h>

int main() {
    const char filePath[] = "./exec_track_kern.o";
    const char bpfObjPath[] = "detect_execve";
    struct bpf_object* bpfObject;
    struct bpf_program* prog;
    int err;
    bpfObject = bpf_object__open_file(filePath, NULL); 
    if (!bpfObject) {
        printf("Error! Failed to load %s\n",filePath);
        return 1;
    }
    err = bpf_object__load(bpfObject);
    if (err) {
        printf("Failed to load %s\n",filePath);
        return 1;
    }
    prog = bpf_object__find_program_by_name(bpfObject, bpfObjPath);
    if (!prog){
        printf("Failed to find eBPF program\n");
         return 1;
    }
    bpf_program__attach(prog);
    while (1) {
    // Intentionally empty.
    }
    return 0;
}
