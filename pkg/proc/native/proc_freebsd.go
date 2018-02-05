package native

// #cgo LDFLAGS: -lprocstat
// #include <stdlib.h>
// #include "proc_freebsd.h"
import "C"
import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	sys "golang.org/x/sys/unix"

	"github.com/derekparker/delve/pkg/proc"
)

// Process statuses
const (
	StatusIO	= 'D'
	StatusIdle	= 'I'
	StatusPending	= 'L'
	StatusRunning   = 'R'
	StatusSleeping  = 'S'
	StatusStopped   = 'T'
	StatusIdleInterrupt = 'W'
	StatusZombie    = 'Z'
)

// OSProcessDetails contains FreeBSD specific
// process details.
type OSProcessDetails struct {
	comm string
}

// Launch creates and begins debugging a new process. First entry in
// `cmd` is the program to run, and then rest are the arguments
// to be supplied to that process. `wd` is working directory of the program.
// XXX Unused by Delve except in the tests
func Launch(cmd []string, wd string) (*Process, error) {
	var (
		process *exec.Cmd
		err     error
	)
	// check that the argument to Launch is an executable file
	if fi, staterr := os.Stat(cmd[0]); staterr == nil && (fi.Mode()&0111) == 0 {
		return nil, proc.NotExecutableErr
	}
	dbp := New(0)
	dbp.execPtraceFunc(func() {
		process = exec.Command(cmd[0])
		process.Args = cmd
		process.Stdout = os.Stdout
		process.Stderr = os.Stderr
		process.SysProcAttr = &syscall.SysProcAttr{Ptrace: true, Setpgid: true}
		if wd != "" {
			process.Dir = wd
		}
		err = process.Start()
	})
	if err != nil {
		return nil, err
	}
	dbp.pid = process.Process.Pid
	dbp.childProcess = true
	_, _, err = dbp.wait(process.Process.Pid, 0)
	if err != nil {
		return nil, fmt.Errorf("waiting for target execve failed: %s", err)
	}
	return initializeDebugProcess(dbp, process.Path)
}

// Attach to an existing process with the given PID.
// XXX Unused by Delve except in the tests
func Attach(pid int) (*Process, error) {
	dbp := New(pid)

	var err error
	dbp.execPtraceFunc(func() { err = PtraceAttach(dbp.pid) })
	if err != nil {
		return nil, err
	}
	_, _, err = dbp.wait(dbp.pid, 0)
	if err != nil {
		return nil, err
	}

	dbp, err = initializeDebugProcess(dbp, "")
	if err != nil {
		dbp.Detach(false)
		return nil, err
	}
	return dbp, nil
}

// Kill kills the target process.
func (dbp *Process) Kill() (err error) {
	if dbp.exited {
		return nil
	}
	if err = sys.Kill(-dbp.pid, sys.SIGKILL); err != nil {
		return errors.New("could not deliver signal " + err.Error())
	}
	// If the process is stopped, we must continue it so it can receive the
	// signal
	PtraceCont(dbp.pid, 0)
	if _, _, err = dbp.wait(dbp.pid, 0); err != nil {
		return
	}
	dbp.postExit()
	return
}

// Used by RequestManualStop
func (dbp *Process) requestManualStop() (err error) {
	return sys.Kill(dbp.pid, sys.SIGTRAP)
}

// Attach to a newly created thread, and store that thread in our list of
// known threads.
func (dbp *Process) addThread(tid int, attach bool) (*Thread, error) {
	if thread, ok := dbp.threads[tid]; ok {
		return thread, nil
	}

	var err error
	dbp.execPtraceFunc(func() { err = sys.PtraceLwpEvents(dbp.pid, 1)})
	if err == syscall.ESRCH {
		// XXX why do we wait here?
		if _, _, err = dbp.waitFast(dbp.pid); err != nil {
			return nil, fmt.Errorf("error while waiting after adding process: %d %s", dbp.pid, err)
		}
	}

	dbp.threads[tid] = &Thread{
		ID:  tid,
		dbp: dbp,
		os:  new(OSSpecificDetails),
	}
	if dbp.currentThread == nil {
		dbp.SwitchThread(tid)
	}
	return dbp.threads[tid], nil
}

// Used by initializeDebugProcess
func (dbp *Process) updateThreadList() error {
	tids := PtraceGetLwpList(dbp.pid)
	for _, tid := range tids {
		if _, err := dbp.addThread(tid, tid != dbp.pid); err != nil {
			return err
		}
	}
	return nil
}

// Used by LoadInformation
func findExecutable(path string, pid int) string {
	if path == "" {
		cstr := C.find_executable(C.int(pid))
		defer C.free(unsafe.Pointer(cstr))
		path = C.GoString(cstr)
	}
	return path
}

// Used by ContinueOnce
func (dbp *Process) trapWait(pid int) (*Thread, error) {
	for {
		wpid, status, err := dbp.wait(pid, 0)
		if err != nil {
			return nil, fmt.Errorf("wait err %s %d", err, pid)
		}
		tid, pl_flags, err := ptraceGetLwpInfo(wpid)
		if err != nil {
			return nil, fmt.Errorf("ptraceGetLwpInfo err %s %d",
				err, pid)
		}
		th, ok := dbp.threads[tid]
		if ok {
			th.Status = (*WaitStatus)(status)
		}
		if status.Exited() {
			dbp.postExit()
			return nil, proc.ProcessExitedError{Pid: wpid, Status: status.ExitStatus()}
			delete(dbp.threads, wpid)
			continue
		}
		if status.StopSignal() == sys.SIGTRAP && (pl_flags & sys.PL_FLAG_BORN != 0) {
			/* TODO
			 * Use ptrace with PT_LWPINFO to figure out if a new
			 * thread was born
			 * Continue if PT_LWPINFO fails or dbp.addThread fails
			 * Attach to the new thread if PL_FLAG_BORN
			 */
			if err != nil {
				if err == sys.ESRCH {
					// process died while we were adding it
					continue
				}
				return nil, fmt.Errorf("could not get event message: %s", err)
			}
			th, err = dbp.addThread(int(tid), false)
			if err != nil {
				if err == sys.ESRCH {
					// process died while we were adding it
					continue
				}
				return nil, err
			}
			if err = th.Continue(); err != nil {
				if err == sys.ESRCH {
					// process died while we were continuing it
					delete(dbp.threads, th.ID)
					continue
				}
				return nil, fmt.Errorf("could not continue new thread %d %s", tid, err)
			}
			// XXX pid != tid
			// XXX The man page is ambiguous about whether
			// PT_CONTINUE affects a single thread or every thread
			// in the process.  I'm guessing the latter.  If not,
			// then we'll have to restart other threads below.
			continue
		}
		if th == nil {
			// Sometimes we get an unknown thread, ignore it?
			continue
		}
		dbp.haltMu.Lock()
		halt := dbp.halt
		dbp.haltMu.Unlock()
		if status.StopSignal() == sys.SIGTRAP && halt {
			dbp.halt = false
			return th, nil
		}
		if status.StopSignal() == sys.SIGTRAP {
			return th, nil
		}
	}
}

// Used by LoadInformation
// Needs to store:
// * command name in dbp.os.comm
func (dbp *Process) loadProcessInformation(wg *sync.WaitGroup) {
	defer wg.Done()

	comm, _ := C.find_command_name(C.int(dbp.pid))
	defer C.free(unsafe.Pointer(comm))
	comm_str := C.GoString(comm)

	dbp.os.comm = strings.Replace(string(comm_str), "%", "%%", -1)
}

// Helper function used here and in threads_freebsd.go
// Return the status symbol
func status(pid int) rune {
	status := rune(C.find_status(C.int(pid)))
	return status
}

// waitFast is like wait but does not handle process-exit correctly
// used by halt and singleStep
func (dbp *Process) waitFast(pid int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	wpid, err := sys.Wait4(pid, &s, 0, nil)
	return wpid, &s, err
}

// Only used in this file
func (dbp *Process) wait(pid, options int) (int, *sys.WaitStatus, error) {
	var s sys.WaitStatus
	wpid, err := sys.Wait4(pid, &s, options, nil)
	return wpid, &s, err
}

// Used by ContinueOnce
func (dbp *Process) setCurrentBreakpoints(trapthread *Thread) error {
	for _, th := range dbp.threads {
		if th.CurrentBreakpoint == nil {
			err := th.SetCurrentBreakpoint()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Used by ContinueOnce
func (dbp *Process) exitGuard(err error) error {
	if err != sys.ESRCH {
		return err
	}
	if status(dbp.pid) == StatusZombie {
		_, err := dbp.trapWait(-1)
		return err
	}

	return err
}

// Used by ContinueOnce and Continue
func (dbp *Process) resume() error {
	// all threads stopped over a breakpoint are made to step over it
	for _, thread := range dbp.threads {
		if thread.CurrentBreakpoint != nil {
			if err := thread.StepInstruction(); err != nil {
				return err
			}
			thread.CurrentBreakpoint = nil
		}
	}
	// everything is resumed
	for _, thread := range dbp.threads {
		if err := thread.resume(); err != nil && err != sys.ESRCH {
			return err
		}
	}
	return nil
}

// Used by Attach and Detach
func (dbp *Process) detach(kill bool) error {
	err := PtraceDetach(dbp.pid, 0)
	if err != nil {
		return err
	}
	if kill {
		return nil
	}
	return nil
}

// Usedy by Detach
func killProcess(pid int) error {
	return sys.Kill(pid, sys.SIGINT)
}
