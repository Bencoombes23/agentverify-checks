"""Owned process trees: no launcher-only cleanup on Windows virtual environments.

Windows children start suspended, enter a private kill-on-close job, then resume.
No commands, service discovery or administrator rights are used for job ownership.
This is lifecycle containment, not a filesystem/network security sandbox.
"""
import ctypes
from ctypes import wintypes
import os
import signal
import subprocess
import time


class WindowsJob:
    def __init__(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel = kernel
        size = ctypes.c_size_t

        class Limits(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", wintypes.DWORD), ("min_working_set", size), ("max_working_set", size),
                        ("active_limit", wintypes.DWORD), ("affinity", size),
                        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]

        class Extended(ctypes.Structure):
            _fields_ = [("basic", Limits), ("io", IO), ("process_memory", size), ("job_memory", size),
                        ("peak_process", size), ("peak_job", size)]

        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in ("user_time", "kernel_time", "period_user", "period_kernel")] + [
                (name, wintypes.DWORD) for name in ("faults", "total", "active", "terminated")]

        self.Accounting = Accounting
        prototypes = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "QueryInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in prototypes.items():
            getattr(kernel, name).argtypes, getattr(kernel, name).restype = args, result
        self.handle = kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            kernel.CloseHandle(self.handle)
            self.handle = None
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_and_resume(self, process):
        k = self.kernel
        if not k.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())

        class ThreadEntry(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in ("size", "usage", "thread_id", "owner_pid")] + [
                ("base_priority", wintypes.LONG), ("delta_priority", wintypes.LONG), ("flags", wintypes.DWORD)]

        k.CreateToolhelp32Snapshot.argtypes, k.CreateToolhelp32Snapshot.restype = [wintypes.DWORD, wintypes.DWORD], wintypes.HANDLE
        k.Thread32First.argtypes = k.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
        k.Thread32First.restype = k.Thread32Next.restype = wintypes.BOOL
        k.OpenThread.argtypes, k.OpenThread.restype = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE
        k.ResumeThread.argtypes, k.ResumeThread.restype = [wintypes.HANDLE], wintypes.DWORD
        snapshot = k.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = k.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.owner_pid == process.pid:
                    thread = k.OpenThread(0x0002, False, entry.thread_id)
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if k.ResumeThread(thread) == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                    finally:
                        k.CloseHandle(thread)
                    return
                found = k.Thread32Next(snapshot, ctypes.byref(entry))
            raise RuntimeError("Owned suspended process thread not found")
        finally:
            k.CloseHandle(snapshot)

    def active(self):
        info = self.Accounting()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return info.active

    def close(self):
        if self.handle is None:
            return
        try:
            if self.active():
                if not self.kernel.TerminateJobObject(self.handle, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                deadline = time.monotonic() + 5
                while self.active() and time.monotonic() < deadline:
                    time.sleep(.01)
                if self.active():
                    raise RuntimeError("Owned job did not drain")
        finally:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class ProcessTree:
    def __init__(self, args, **kwargs):
        self.job = WindowsJob() if os.name == "nt" else None
        self.closed = False
        self.stopped = False
        self.process = None
        try:
            if self.job is not None:
                kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x00000004 | 0x08000000
            else:
                kwargs["start_new_session"] = True
            self.process = subprocess.Popen(args, **kwargs)
            if self.job is not None:
                self.job.assign_and_resume(self.process)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        try:
            if self.job is not None:
                self.job.close()
            elif self.process is not None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if self.process is not None:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=5)
            self.stopped = True
        finally:
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def capture(args, *, timeout, **kwargs):
    with ProcessTree(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs) as tree:
        try:
            out, err = tree.process.communicate(timeout=timeout)
            return tree.process.returncode, out + err
        except subprocess.TimeoutExpired:
            tree.close()  # Kill the whole owned tree before draining inherited pipes.
            out, err = tree.process.communicate(timeout=5)
            return 124, out + err + "\nOwned process tree timed out and was stopped\n"
