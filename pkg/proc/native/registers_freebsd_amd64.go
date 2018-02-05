package native

import "C"
import (
	"golang.org/x/arch/x86/x86asm"
	sys "golang.org/x/sys/unix"

	"github.com/derekparker/delve/pkg/proc"
)

// Regs is a wrapper for sys.PtraceRegs.
type Regs struct {
	regs   *sys.Reg
	fsBase uint64
	fpregs []proc.Register
}

func (r *Regs) Slice() []proc.Register {
	var regs64 = []struct {
		k string
		v int64
	}{
		{"R15", r.regs.R15},
		{"R14", r.regs.R14},
		{"R13", r.regs.R13},
		{"R12", r.regs.R12},
		{"R11", r.regs.R11},
		{"R10", r.regs.R10},
		{"R9", r.regs.R9},
		{"R8", r.regs.R8},
		{"Rdi", r.regs.Rdi},
		{"Rsi", r.regs.Rsi},
		{"Rbp", r.regs.Rbp},
		{"Rbx", r.regs.Rbx},
		{"Rdx", r.regs.Rdx},
		{"Rcx", r.regs.Rcx},
		{"Rax", r.regs.Rax},
		{"Rip", r.regs.Rip},
		{"Cs", r.regs.Cs},
		{"Rflags", r.regs.Rflags},
		{"Rsp", r.regs.Rsp},
		{"Ss", r.regs.Ss},
	}
	var regs32 = []struct {
		k string
		v uint32
	}{
		{"Trapno", r.regs.Trapno},
		{"Err", r.regs.Err},
	}
	var regs16 = []struct {
		k string
		v uint16
	}{
		{"Fs", r.regs.Fs},
		{"Gs", r.regs.Gs},
		{"Es", r.regs.Es},
		{"Ds", r.regs.Ds},
	}
	out := make([]proc.Register, 0,
		len(regs64) +
		len(regs32) +
		len(regs16) +
		1 +			// for Rflags
		len(r.fpregs))
	for _, reg := range regs64 {
		// FreeBSD defines the registers as signed, but Linux defines
		// them as unsigned.  Of course, a register doesn't really have
		// a concept of signedness.  Cast to what Delve expects.
		out = proc.AppendQwordReg(out, reg.k, uint64(reg.v))
	}
	for _, reg := range regs32 {
		out = proc.AppendDwordReg(out, reg.k, reg.v)
	}
	for _, reg := range regs16 {
		out = proc.AppendWordReg(out, reg.k, reg.v)
	}
	// x86 called this register "Eflags".  amd64 extended it and renamed it
	// "Rflags", but Linux still uses the old name.
	out = proc.AppendEflagReg(out, "Rflags", uint64(r.regs.Rflags))
	out = append(out, r.fpregs...)
	return out
}

// PC returns the value of RIP register.
func (r *Regs) PC() uint64 {
	return uint64(r.regs.PC())
}

// SP returns the value of RSP register.
func (r *Regs) SP() uint64 {
	return uint64(r.regs.Rsp)
}

func (r *Regs) BP() uint64 {
	return uint64(r.regs.Rbp)
}

// CX returns the value of RCX register.
func (r *Regs) CX() uint64 {
	return uint64(r.regs.Rcx)
}

// TLS returns the address of the thread
// local storage memory segment.
// TODO: implement it
func (r *Regs) TLS() uint64 {
	// Based on FS.base for amd64 and GS.base for i386
	return r.fsBase
}

func (r *Regs) GAddr() (uint64, bool) {
	return 0, false
}

// SetPC sets RIP to the value specified by 'pc'.
func (r *Regs) SetPC(t proc.Thread, pc uint64) (err error) {
	thread := t.(*Thread)
	r.regs.SetPC(int64(pc))
	thread.dbp.execPtraceFunc(func() { err = sys.PtraceSetRegs(thread.ID, r.regs) })
	return
}

func (r *Regs) Get(n int) (uint64, error) {
	reg := x86asm.Reg(n)
	const (
		mask8  = 0x000f
		mask16 = 0x00ff
		mask32 = 0xffff
	)

	switch reg {
	// 8-bit
	case x86asm.AL:
		return uint64(r.regs.Rax) & mask8, nil
	case x86asm.CL:
		return uint64(r.regs.Rcx) & mask8, nil
	case x86asm.DL:
		return uint64(r.regs.Rdx) & mask8, nil
	case x86asm.BL:
		return uint64(r.regs.Rbx) & mask8, nil
	case x86asm.AH:
		return (uint64(r.regs.Rax) >> 8) & mask8, nil
	case x86asm.CH:
		return (uint64(r.regs.Rcx) >> 8) & mask8, nil
	case x86asm.DH:
		return (uint64(r.regs.Rdx) >> 8) & mask8, nil
	case x86asm.BH:
		return (uint64(r.regs.Rbx) >> 8) & mask8, nil
	case x86asm.SPB:
		return uint64(r.regs.Rsp) & mask8, nil
	case x86asm.BPB:
		return uint64(r.regs.Rbp) & mask8, nil
	case x86asm.SIB:
		return uint64(r.regs.Rsi) & mask8, nil
	case x86asm.DIB:
		return uint64(r.regs.Rdi) & mask8, nil
	case x86asm.R8B:
		return uint64(r.regs.R8) & mask8, nil
	case x86asm.R9B:
		return uint64(r.regs.R9) & mask8, nil
	case x86asm.R10B:
		return uint64(r.regs.R10) & mask8, nil
	case x86asm.R11B:
		return uint64(r.regs.R11) & mask8, nil
	case x86asm.R12B:
		return uint64(r.regs.R12) & mask8, nil
	case x86asm.R13B:
		return uint64(r.regs.R13) & mask8, nil
	case x86asm.R14B:
		return uint64(r.regs.R14) & mask8, nil
	case x86asm.R15B:
		return uint64(r.regs.R15) & mask8, nil

	// 16-bit
	case x86asm.AX:
		return uint64(r.regs.Rax) & mask16, nil
	case x86asm.CX:
		return uint64(r.regs.Rcx) & mask16, nil
	case x86asm.DX:
		return uint64(r.regs.Rdx) & mask16, nil
	case x86asm.BX:
		return uint64(r.regs.Rbx) & mask16, nil
	case x86asm.SP:
		return uint64(r.regs.Rsp) & mask16, nil
	case x86asm.BP:
		return uint64(r.regs.Rbp) & mask16, nil
	case x86asm.SI:
		return uint64(r.regs.Rsi) & mask16, nil
	case x86asm.DI:
		return uint64(r.regs.Rdi) & mask16, nil
	case x86asm.R8W:
		return uint64(r.regs.R8) & mask16, nil
	case x86asm.R9W:
		return uint64(r.regs.R9) & mask16, nil
	case x86asm.R10W:
		return uint64(r.regs.R10) & mask16, nil
	case x86asm.R11W:
		return uint64(r.regs.R11) & mask16, nil
	case x86asm.R12W:
		return uint64(r.regs.R12) & mask16, nil
	case x86asm.R13W:
		return uint64(r.regs.R13) & mask16, nil
	case x86asm.R14W:
		return uint64(r.regs.R14) & mask16, nil
	case x86asm.R15W:
		return uint64(r.regs.R15) & mask16, nil

	// 32-bit
	case x86asm.EAX:
		return uint64(r.regs.Rax) & mask32, nil
	case x86asm.ECX:
		return uint64(r.regs.Rcx) & mask32, nil
	case x86asm.EDX:
		return uint64(r.regs.Rdx) & mask32, nil
	case x86asm.EBX:
		return uint64(r.regs.Rbx) & mask32, nil
	case x86asm.ESP:
		return uint64(r.regs.Rsp) & mask32, nil
	case x86asm.EBP:
		return uint64(r.regs.Rbp) & mask32, nil
	case x86asm.ESI:
		return uint64(r.regs.Rsi) & mask32, nil
	case x86asm.EDI:
		return uint64(r.regs.Rdi) & mask32, nil
	case x86asm.R8L:
		return uint64(r.regs.R8) & mask32, nil
	case x86asm.R9L:
		return uint64(r.regs.R9) & mask32, nil
	case x86asm.R10L:
		return uint64(r.regs.R10) & mask32, nil
	case x86asm.R11L:
		return uint64(r.regs.R11) & mask32, nil
	case x86asm.R12L:
		return uint64(r.regs.R12) & mask32, nil
	case x86asm.R13L:
		return uint64(r.regs.R13) & mask32, nil
	case x86asm.R14L:
		return uint64(r.regs.R14) & mask32, nil
	case x86asm.R15L:
		return uint64(r.regs.R15) & mask32, nil

	// 64-bit
	case x86asm.RAX:
		return uint64(r.regs.Rax), nil
	case x86asm.RCX:
		return uint64(r.regs.Rcx), nil
	case x86asm.RDX:
		return uint64(r.regs.Rdx), nil
	case x86asm.RBX:
		return uint64(r.regs.Rbx), nil
	case x86asm.RSP:
		return uint64(r.regs.Rsp), nil
	case x86asm.RBP:
		return uint64(r.regs.Rbp), nil
	case x86asm.RSI:
		return uint64(r.regs.Rsi), nil
	case x86asm.RDI:
		return uint64(r.regs.Rdi), nil
	case x86asm.R8:
		return uint64(r.regs.R8), nil
	case x86asm.R9:
		return uint64(r.regs.R9), nil
	case x86asm.R10:
		return uint64(r.regs.R10), nil
	case x86asm.R11:
		return uint64(r.regs.R11), nil
	case x86asm.R12:
		return uint64(r.regs.R12), nil
	case x86asm.R13:
		return uint64(r.regs.R13), nil
	case x86asm.R14:
		return uint64(r.regs.R14), nil
	case x86asm.R15:
		return uint64(r.regs.R15), nil
	}

	return 0, proc.UnknownRegisterError
}

func registers(thread *Thread, floatingPoint bool) (proc.Registers, error) {
	var (
		regs sys.Reg
		err  error
	)
	thread.dbp.execPtraceFunc(func() {
		err = sys.PtraceGetRegs(thread.ID, &regs)
	})
	if err != nil {
		return nil, err
	}
	var fsbase int64
	err = sys.PtraceGetFsBase(thread.ID, &fsbase)
	if err != nil {
		return nil, err
	}
	r := &Regs{&regs, uint64(fsbase), nil}
	if floatingPoint {
		r.fpregs, err = thread.fpRegisters()
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

const (
	_X86_XSTATE_MAX_SIZE = 2688
	_NT_X86_XSTATE       = 0x202

	_XSAVE_HEADER_START          = 512
	_XSAVE_HEADER_LEN            = 64
	_XSAVE_EXTENDED_REGION_START = 576
	_XSAVE_SSE_REGION_LEN        = 416
)

func (thread *Thread) fpRegisters() (regs []proc.Register, err error) {
	var fpregs proc.LinuxX86Xstate
	thread.dbp.execPtraceFunc(func() { fpregs, err = PtraceGetRegset(thread.ID) })
	regs = fpregs.Decode()
	return
}
