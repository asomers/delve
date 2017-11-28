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
	if !dbp.threads[dbp.pid].Stopped() {
		return errors.New("process must be stopped in order to kill it")
	}
	if err = sys.Kill(-dbp.pid, sys.SIGKILL); err != nil {
		return errors.New("could not deliver signal " + err.Error())
	}
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
	if attach {
		dbp.execPtraceFunc(func() { err = sys.PtraceAttach(tid) })
		if err != nil && err != sys.EBUSY {
			// Do not return err if err == EBUSY,
			// we may already be tracing this thread due to
			// PTRACE_LWP.
			return nil, fmt.Errorf("could not attach to new thread %d %s", tid, err)
		}
		pid, status, err := dbp.waitFast(tid)
		if err != nil {
			return nil, err
		}
		if status.Exited() {
			return nil, fmt.Errorf("thread already exited %d", pid)
		}
	}

	dbp.execPtraceFunc(func() { err = sys.PtraceLwpEvents(tid, 1)})
	if err == syscall.ESRCH {
		if _, _, err = dbp.waitFast(tid); err != nil {
			return nil, fmt.Errorf("error while waiting after adding thread: %d %s", tid, err)
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
		if wpid == 0 {
			continue
		}
		th, ok := dbp.threads[wpid]
		if ok {
			th.Status = (*WaitStatus)(status)
		}
		if status.Exited() {
			if wpid == dbp.pid {
				dbp.postExit()
				return nil, proc.ProcessExitedError{Pid: wpid, Status: status.ExitStatus()}
			}
			delete(dbp.threads, wpid)
			continue
		}
		if status.StopSignal() == sys.SIGTRAP {
			/* TODO
			 * Use ptrace with PT_LWPINFO to figure out if a new
			 * thread was born
			 * Continue if PT_LWPINFO fails or dbp.addThread fails
			 * Attach to the new thread if PL_FLAG_BORN
			 */
			cloned, err := ptraceGetNewLwp(wpid)
			if err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					continue
				}
				return nil, fmt.Errorf("could not get event message: %s", err)
			}
			th, err = dbp.addThread(int(cloned), false)
			if err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					continue
				}
				return nil, err
			}
			if err = th.Continue(); err != nil {
				if err == sys.ESRCH {
					// thread died while we were adding it
					delete(dbp.threads, th.ID)
					continue
				}
				return nil, fmt.Errorf("could not continue new thread %d %s", cloned, err)
			}
			if err = dbp.threads[int(wpid)].Continue(); err != nil {
				if err != sys.ESRCH {
					return nil, fmt.Errorf("could not continue existing thread %d %s", wpid, err)
				}
			}
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
			th.running = false
			dbp.halt = false
			return th, nil
		}
		if status.StopSignal() == sys.SIGTRAP {
			th.running = false
			return th, nil
		}
		if th != nil {
			// TODO(dp) alert user about unexpected signals here.
			if err := th.resumeWithSig(int(status.StopSignal())); err != nil {
				if err == sys.ESRCH {
					return nil, proc.ProcessExitedError{Pid: dbp.pid}
				}
				return nil, err
			}
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
	if (pid != dbp.pid) || (options != 0) {
		wpid, err := sys.Wait4(pid, &s, options, nil)
		return wpid, &s, err
	}
	// If we call wait4/waitpid on a thread that is the leader of its group,
	// with options == 0, while ptracing and the thread leader has exited leaving
	// zombies of its own then waitpid hangs forever this is apparently intended
	// behaviour in the linux kernel because it's just so convenient.
	// Therefore we call wait4 in a loop with WNOHANG, sleeping a while between
	// calls and exiting when either wait4 succeeds or we find out that the thread
	// has become a zombie.
	// References:
	// https://sourceware.org/bugzilla/show_bug.cgi?id=12702
	// https://sourceware.org/bugzilla/show_bug.cgi?id=10095
	// https://sourceware.org/bugzilla/attachment.cgi?id=5685
	for {
		wpid, err := sys.Wait4(pid, &s, sys.WNOHANG|options, nil)
		if err != nil {
			return 0, nil, err
		}
		if wpid != 0 {
			return wpid, &s, err
		}
		if status(pid) == StatusZombie {
			return pid, nil, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
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
	for threadID := range dbp.threads {
		err := PtraceDetach(threadID, 0)
		if err != nil {
			return err
		}
	}
	if kill {
		return nil
	}
	// For some reason the process will sometimes enter stopped state after a
	// detach, this doesn't happen immediately either.
	// We have to wait a bit here, then check if the main thread is stopped and
	// SIGCONT it if it is.
	time.Sleep(50 * time.Millisecond)
	if s := status(dbp.pid); s == 'T' {
		sys.Kill(dbp.pid, sys.SIGCONT)
	}
	return nil
}

// Usedy by Detach
func killProcess(pid int) error {
	return sys.Kill(pid, sys.SIGINT)
}
