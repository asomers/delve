package native

// #include <sys/thr.h>
import "C"
import (
	"fmt"

	sys "golang.org/x/sys/unix"

	"github.com/derekparker/delve/pkg/proc"
)

type WaitStatus sys.WaitStatus

// OSSpecificDetails hold Linux specific
// process details.
type OSSpecificDetails struct {
	registers sys.Reg
}

func (t *Thread) halt() (err error) {
	_, err = C.thr_kill2(C.pid_t(t.dbp.pid), C.long(t.ID),
			     C.int(sys.SIGSTOP))
	if err != nil {
		err = fmt.Errorf("halt err %s on thread %d", err, t.ID)
		return
	}
	// If the process is stopped, we must continue it so it can receive the
	// signal
	PtraceCont(t.ID, 0)
	_, _, err = t.dbp.waitFast(t.dbp.pid)
	if err != nil {
		err = fmt.Errorf("wait err %s on thread %d", err, t.ID)
		return
	}
	return
}

func (t *Thread) stopped() bool {
	state := status(t.ID)
	return state == StatusStopped
}

func (t *Thread) resume() error {
	return t.resumeWithSig(0)
}

func (t *Thread) resumeWithSig(sig int) (err error) {
	t.running = true
	t.dbp.execPtraceFunc(func() { err = PtraceCont(t.ID, sig) })
	return
}

func (t *Thread) singleStep() (err error) {
	for {
		t.dbp.execPtraceFunc(func() { err = sys.PtraceSingleStep(t.ID) })
		if err != nil {
			return err
		}
		wpid, status, err := t.dbp.waitFast(t.ID)
		if err != nil {
			return err
		}
		if (status == nil || status.Exited()) && wpid == t.dbp.pid {
			t.dbp.postExit()
			rs := 0
			if status != nil {
				rs = status.ExitStatus()
			}
			return proc.ProcessExitedError{Pid: t.dbp.pid, Status: rs}
		}
		if wpid == t.ID && status.StopSignal() == sys.SIGTRAP {
			return nil
		}
	}
}

func (t *Thread) Blocked() bool {
	regs, err := t.Registers(false)
	if err != nil {
		return false
	}
	pc := regs.PC()
	fn := t.BinInfo().PCToFunc(pc)
	if fn != nil && (fn.Name == "runtime.usleep") {
		return true
	}
	return false
}

func (t *Thread) WriteMemory(addr uintptr, data []byte) (written int, err error) {
	if t.dbp.exited {
		return 0, proc.ProcessExitedError{Pid: t.dbp.pid}
	}
	if len(data) == 0 {
		return
	}
	t.dbp.execPtraceFunc(func() {
		written, err = ptraceWriteData(t.ID, addr, data)
	})
	return
}

func (t *Thread) ReadMemory(data []byte, addr uintptr) (n int, err error) {
	if t.dbp.exited {
		return 0, proc.ProcessExitedError{Pid: t.dbp.pid}
	}
	if len(data) == 0 {
		return
	}
	t.dbp.execPtraceFunc(func() {
		n, err = ptraceReadData(t.ID, addr, data)
	})
	return
}
