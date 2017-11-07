#include <sys/types.h>
#include <sys/ptrace.h>

#include "ptrace_freebsd_amd64.h"

// Reads the X86 XSAVE area into a buffer and returns a pointer to it in the
// xsave argument.  Returns the buffer's length.  Returns 0 on failure.  Must
// be freed when no longer in use.
size_t
ptrace_get_xsave(int tid, unsigned char **xsave) {
	static ssize_t xsave_len = 0;
	unsigned char *buf;
	int err;

	if (xsave_len == 0) {
		// Haven't tried to set the size yet
		struct ptrace_xstate_info info;
		err = ptrace(PT_GETXSTATE_INFO, (pid_t)tid,
			     (caddr_t)&info, sizeof(info));
		if (err == 0) {
			xsave_len = info.xsave_len;
		} else {
			xsave_len = -1;
		}
	}
	if (xsave_len < 0) {
		// Not supported on this system
		return (NULL);
	}

	buf = malloc(xsave_len);
	if (buf == NULL)
		return (NULL);
	err = ptrace(PT_GETXSTATE, (pid_t)tid, (caddr_t)buf, xsave_len);
	return (xsave);
}
