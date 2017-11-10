#include <sys/types.h>
#include <sys/ptrace.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ptrace_freebsd_amd64.h"

/*
 * Fetches the list of LWPs for a given process into tids.  Returns the number
 * of LWP entries filled in.  Sets errno on return.
 */
int
ptrace_get_lwp_list(int tid, int *tids, size_t len) {
	int ret;

	errno = 0;
	ret = ptrace(PT_GETLWPLIST, (pid_t)tid, (caddr_t)&tids, len);
	return (ret);
}

/*
 * Returns a pointer to the X86 XSAVE data, or NULL on failure.  Returns the
 * length of the buffer in the len argument.  Must be freed when no longer in
 * use.  Modifies errno.
 */
unsigned char*
ptrace_get_xsave(int tid, size_t *len) {
	static ssize_t xsave_len = 0;
	static int getxstate_info_errno = 0;
	unsigned char *buf;
	int err;

	if (xsave_len == 0) {
		/* Haven't tried to set the size yet */
		struct ptrace_xstate_info info;
		err = ptrace(PT_GETXSTATE_INFO, (pid_t)tid,
			     (caddr_t)&info, sizeof(info));
		if (err == 0)
			xsave_len = info.xsave_len;
		else {
			xsave_len = -1;
			getxstate_info_errno = errno;
		}
	}
	if (xsave_len < 0) {
		/* Not supported on this system */
		errno = getxstate_info_errno;
		return (NULL);
	}

	buf = malloc(xsave_len);
	if (buf == NULL) {
		errno;
		return (NULL);
	}
	err = ptrace(PT_GETXSTATE, (pid_t)tid, (caddr_t)buf, xsave_len);
	if (err == 0) {
		errno = 0;
		*len = xsave_len;
		return (buf);
	} else {
		free(buf);
		return (NULL);
	}
}

int
ptrace_lwp_info(int tid, struct ptrace_lwpinfo *info) {
	return (ptrace(PT_LWPINFO, tid, (caddr_t)info, sizeof(*info)));
}

static int
ptrace_read(int req, int tid, uintptr_t addr, void *buf, size_t len) {
	/*
	 * PT_READ_[ID] operates on ints, not bytes.  First, read a fraction of
	 * an int if the request was unaligned
	 */
	if (addr % sizeof(int) != 0) {
		void *stubaddr;
		size_t stublen;
		int value;

		stubaddr = (void*)(addr - addr % sizeof(int));
		stublen = MAX(len, sizeof(int) - addr % sizeof(int));
		errno = 0;
		value = ptrace(req, tid, (caddr_t)stubaddr, 0);
		if (errno != 0)
			return (-1);
		memmove(buf, &value + addr % sizeof(int), stublen);
		addr += stublen;
		buf += stublen;
		len -= stublen;
	}

	/* Now read the rest */
	for (; len > 0; len -= sizeof(int),
			addr += sizeof(int),
			buf += sizeof(int)) {
		int value;

		errno = 0;
		value = ptrace(req, tid, (caddr_t)addr, 0);
		if (errno != 0)
			return (-1);
		memmove(buf, &value, MAX(len, sizeof(int)));
	}
	return (0);
}

/*
 * Read len bytes of data from the process's address space beginning at addr
 * into buf
 */
int
ptrace_read_d(int tid, uintptr_t addr, void *buf, size_t len) {
	return (ptrace_read(PT_READ_D, tid, addr, buf, len));
}

/*
 * Read len bytes of instructions from the process's address space beginning at
 * addr into buf
 */
int
ptrace_read_i(int tid, uintptr_t addr, void *buf, size_t len) {
	return (ptrace_read(PT_READ_I, tid, addr, buf, len));
}

static int
ptrace_write(int req, int tid, uintptr_t addr, void *buf, size_t len) {
	/*
	 * PT_WRITE_[ID] operates on ints, not bytes.  First, write a fraction
	 * of an int if the request was unaligned
	 */
	if (addr % sizeof(int) != 0) {
		int value;
		void *stubaddr;
		size_t stublen;

		stubaddr = (void*)(addr - addr % sizeof(int));
		stublen = MAX(len, sizeof(int) - addr % sizeof(int));
		memmove(&value + addr % sizeof(int), buf, stublen);
		if (ptrace(req, tid, (caddr_t)stubaddr, value) < 0)
			return (-1);
		addr += stublen;
		buf += stublen;
		len -= stublen;
	}

	/* Now write the rest */
	for (; len > 0; len -= sizeof(int),
			buf += sizeof(int),
			addr += sizeof(int)) {
		int value;

		memmove(&value, buf, MAX(len, sizeof(int)));
		if (ptrace(req, tid, (caddr_t)addr, value) < 0)
			return (-1);
	}
	return (0);
}

/*
 * Write len bytes of data from buf into the process's address space beginning
 * at addr
 *
 */
int
ptrace_write_d(int tid, uintptr_t addr, void *buf, size_t len) {
	return (ptrace_write(PT_WRITE_D, tid, addr, buf, len));
}

/*
 * Write len bytes of instructions from buf into the process's address space
 * beginning at addr
 */
int
ptrace_write_i(int tid, uintptr_t addr, void *buf, size_t len) {
	return (ptrace_write(PT_WRITE_I, tid, addr, buf, len));
}
