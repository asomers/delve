package native

// #cgo LDFLAGS: -lutil
//#include <sys/types.h>
//#include <sys/ptrace.h>
//
// #include <stdlib.h>
// #include "ptrace_freebsd_amd64.h"
import "C"

import (
	"syscall"
	"unsafe"

	"github.com/derekparker/delve/pkg/proc"
)

import sys "golang.org/x/sys/unix"

// PtraceAttach executes the sys.PtraceAttach call.
// pid must be a PID, not a LWPID
func PtraceAttach(pid int) error {
	return sys.PtraceAttach(pid)
}

// PtraceDetach calls ptrace(PTRACE_DETACH).
func PtraceDetach(pid, sig int) error {
	_, _, err := sys.Syscall6(sys.SYS_PTRACE, sys.PTRACE_DETACH, uintptr(pid), 1, uintptr(sig), 0, 0)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

// PtraceCont executes ptrace PTRACE_CONT
// id may be a PID or an LWPID
func PtraceCont(id, sig int) error {
	return sys.PtraceCont(id, sig)
}

// PtraceSingleStep executes ptrace PTRACE_SINGLE_STEP.
// id may be a PID or an LWPID
func PtraceSingleStep(id int) error {
	return sys.PtraceSingleStep(id)
}

// Get a list of the thread ids of a process
func PtraceGetLwpList(pid int) (tids []int) {
	// 1500 is the default maximum threads per process.  TODO: get this
	// from a sysctl.
	tids = make([]int, 1500)
	n, _ := C.ptrace_get_lwp_list(C.int(pid),
				      (*C.int)(unsafe.Pointer(&tids[0])),
				      1500);
	// XXX What is the appropriate action on error?
	return tids[0:n]
}

// Get the lwpid_t of the thread that caused wpid's process to stop, if any.
// Return also the full pl_flags variable, which indicates why the process
// stopped.
func ptraceGetLwpInfo(wpid int) (new_lwpid int, pl_flags int, err error) {
	var info C.struct_ptrace_lwpinfo
	_, err = C.ptrace_lwp_info(C.int(wpid), &info);
	if (err == nil) {
		new_lwpid = int(info.pl_lwpid)
		pl_flags = int(info.pl_flags)
	} else {
		new_lwpid = -1
	}
	return new_lwpid, pl_flags, err
}

// PtraceGetRegset returns floating point registers of the specified thread
// using PTRACE.
// See amd64_linux_fetch_inferior_registers in gdb/amd64-linux-nat.c.html
// and amd64_supply_xsave in gdb/amd64-tdep.c.html
// and Section 13.1 (and following) of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1: Basic Architecture
// id may be a PID or an LWPID
func PtraceGetRegset(id int) (regset proc.LinuxX86Xstate, err error) {
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETFPREGS, uintptr(id), uintptr(0), uintptr(unsafe.Pointer(&regset.PtraceFpRegs)), 0, 0)
	if err == syscall.Errno(0) {
		var xsave_len C.size_t
		xsave, _ := C.ptrace_get_xsave(C.int(id), &xsave_len)
		defer C.free(unsafe.Pointer(xsave))
		if xsave != nil {
			xsave_sl := C.GoBytes(unsafe.Pointer(xsave),
					      C.int(xsave_len))
			err = proc.LinuxX86XstateRead(xsave_sl, false, &regset)
		}
	}
	return regset, err
}

// id may be a PID or an LWPID
func ptraceReadData(id int, addr uintptr, data []byte) (n int, err error) {
	_, e := C.ptrace_read_d(C.int(id), C.uintptr_t(addr),
				unsafe.Pointer(&data[0]), C.ssize_t(len(data)))
	if err == syscall.Errno(0) {
		return int(n), e
	} else {
		return 0, e
	}
}

// id may be a PID or an LWPID
func ptraceWriteData(id int, addr uintptr, data []byte) (n int, err error) {
	_, err = C.ptrace_write_d(C.int(id), C.uintptr_t(addr),
				 unsafe.Pointer(&data[0]), C.ssize_t(len(data)))
	if err == syscall.Errno(0) {
		return int(n), err
	} else {
		return 0, err
	}
}
