#include <stddef.h>

struct ptrace_lwpinfo;

unsigned char* ptrace_get_xsave(int tid, size_t *len);
int ptrace_get_lwp_list(int tid, int *tids, size_t len);
int ptrace_lwp_info(int tid, struct ptrace_lwpinfo *info);
int ptrace_read_d(int tid, uintptr_t addr, void *buf, ssize_t len);
int ptrace_read_i(int tid, uintptr_t addr, void *buf, ssize_t len);
int ptrace_write_d(int tid, uintptr_t addr, void *buf, ssize_t len);
int ptrace_write_i(int tid, uintptr_t addr, void *buf, ssize_t len);
