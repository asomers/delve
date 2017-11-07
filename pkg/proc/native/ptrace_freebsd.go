package native

// #include "ptrace_freebsd.h"

import (
	"syscall"
	"unsafe"

	sys "golang.org/x/sys/unix"

	"github.com/derekparker/delve/pkg/proc"
)

// PtraceAttach executes the sys.PtraceAttach call.
func PtraceAttach(pid int) error {
	return sys.PtraceAttach(pid)
}

// PtraceDetach calls ptrace(PTRACE_DETACH).
func PtraceDetach(tid, sig int) error {
	_, _, err := sys.Syscall6(sys.SYS_PTRACE, sys.PTRACE_DETACH, uintptr(tid), 1, uintptr(sig), 0, 0)
	if err != syscall.Errno(0) {
		return err
	}
	return nil
}

// PtraceCont executes ptrace PTRACE_CONT
func PtraceCont(tid, sig int) error {
	return sys.PtraceCont(tid, sig)
}

// PtraceSingleStep executes ptrace PTRACE_SINGLE_STEP.
func PtraceSingleStep(tid int) error {
	return sys.PtraceSingleStep(tid)
}

// Get a list of the thread ids of a process
func PtraceGetLwpList(tid int) (tids []int32) {
	// 1500 is the default maximum threads per process.  TODO: get this
	// from a sysctl.
	var tids = make([]int32, 1500)
	// The ptrace libc call returns the number of LWPs.  But which one of
	// syscall.Syscall6's three return values corresponds?  I don't fucking
	// know, and there is no documentation for syscall.Syscall6.
	pret = ptrace(sys.PTRACE_GETLWPLIST, tid, unsafe.Pointer(&tids), 1500));
	return tids[0:pret]
}

// PtraceGetRegset returns floating point registers of the specified thread
// using PTRACE.
// See amd64_linux_fetch_inferior_registers in gdb/amd64-linux-nat.c.html
// and amd64_supply_xsave in gdb/amd64-tdep.c.html
// and Section 13.1 (and following) of Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 1: Basic Architecture
func PtraceGetRegset(tid int) (regset proc.LinuxX86Xstate, err error) {
	_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETFPREGS, uintptr(tid), uintptr(0), uintptr(unsafe.Pointer(&regset.PtraceFpRegs)), 0, 0)
	if err == syscall.Errno(0) {
		err = nil
	}

	xsave = C.ptrace_get_xsave(tid)
	if xsave != nil {
		proc.LinuxX86stateRead(xsave
	}
	// AWS: TODO: figure out how to port this part.  I'm not entirely sure
	// what an XSAVE area is.
	//var xstateargs [_X86_XSTATE_MAX_SIZE]byte
	//iov := sys.Iovec{Base: &xstateargs[0], Len: _X86_XSTATE_MAX_SIZE}
	//_, _, err = syscall.Syscall6(syscall.SYS_PTRACE, sys.PTRACE_GETREGSET, uintptr(tid), _NT_X86_XSTATE, uintptr(unsafe.Pointer(&iov)), 0, 0)
	//if err != syscall.Errno(0) {
		//return
	//} else {
		//err = nil
	//}

	//err = proc.LinuxX86XstateRead(xstateargs[:iov.Len], false, &regset)
	return regset, err
}

func ptrace(request, pid int, addr uintptr, data uintptr) (err error) {
        _, _, err = sys.Syscall6(sys.SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
        return
}
