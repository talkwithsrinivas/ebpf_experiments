##kernel space
clang -O2 -target bpf -c exec_track_kern.c -o exec_track_kern.o
##user space
clang -O2 -g -Wall -I /usr/include -I /usr/include/bpf -lbpf -o exec_track exec_track.c
