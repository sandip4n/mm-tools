#!/usr/bin/python

from __future__ import division
from __future__ import print_function

from bcc import BPF
import argparse
import ctypes
import os
import re
import subprocess

bpf_text = """
#include <linux/mm.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct mmap_lock_data_t {
    struct mmap_lock_key_t {
        unsigned int pid;
        unsigned int tgid;
        unsigned int is_write;
        struct mm_struct *mm;
    } key;

    unsigned int n_attempts;
    unsigned long ts_last_start;
    unsigned long ts_last_acquire;
    unsigned long ts_last_release;
    unsigned long lat_acquire;
    unsigned long lat_release;
    char comm[TASK_COMM_LEN];
};

BPF_ARRAY(pid_map, unsigned int);
BPF_HASH(mmap_lock_map, struct mmap_lock_key_t, struct mmap_lock_data_t);
BPF_PERF_OUTPUT(mmap_lock_release_events);
BPF_PERF_OUTPUT(mmap_lock_anomaly_events);

static inline int __filter_pid(unsigned int pid)
{
    unsigned int zero = 0, *val;
    val = pid_map.lookup(&zero);
    return val && !(val && pid == *val);
}

TRACEPOINT_PROBE(mmap_lock, mmap_lock_start_locking)
{
    struct mmap_lock_data_t *prev, data = { 0 };
    struct mmap_lock_key_t key = { 0 };
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    key.pid = task->pid;
    key.tgid = task->tgid;
    key.is_write = args->write;
    key.mm = args->mm;

    if (__filter_pid(task->pid) &&
        __filter_pid(task->real_parent->tgid))
        return 0;

    prev = mmap_lock_map.lookup(&key);
    if (!prev) {
        /* first attempt to acquire */
        data.key = key;
        data.ts_last_start = bpf_ktime_get_ns();
        data.n_attempts++;
        mmap_lock_map.insert(&data.key, &data);
    } else if (prev->n_attempts > 0) {
        /* any previous attempts to acquire */
        prev->ts_last_start = bpf_ktime_get_ns();
        prev->n_attempts++;
        mmap_lock_map.update(&prev->key, prev);
    }

    return 0;
}

TRACEPOINT_PROBE(mmap_lock, mmap_lock_acquire_returned)
{
    struct mmap_lock_key_t key = { 0 };
    struct mmap_lock_data_t *prev;
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    key.pid = task->pid;
    key.tgid = task->tgid;
    key.is_write = args->write;
    key.mm = args->mm;

    if (__filter_pid(key.pid) &&
        __filter_pid(task->real_parent->tgid))
        return 0;

    prev = mmap_lock_map.lookup(&key);
    if (prev && prev->n_attempts > 0) {
        /* any previous attempts to acquire */
        if (args->success) {
            prev->ts_last_acquire = bpf_ktime_get_ns();
            prev->lat_acquire += prev->ts_last_acquire - prev->ts_last_start;
            mmap_lock_map.update(&prev->key, prev);
        }
    }

    return 0;
}

TRACEPOINT_PROBE(mmap_lock, mmap_lock_released)
{
    struct mmap_lock_key_t key = { 0 };
    struct mmap_lock_data_t *prev;
    struct task_struct *task;

    task = (struct task_struct *) bpf_get_current_task();
    key.pid = task->pid;
    key.tgid = task->tgid;
    key.is_write = args->write;
    key.mm = args->mm;

    if (__filter_pid(key.pid) &&
        __filter_pid(task->real_parent->tgid))
        return 0;

    prev = mmap_lock_map.lookup(&key);
    if (prev && prev->n_attempts > 0) {
        /* any previous attempts to acquire */
        prev->ts_last_release = bpf_ktime_get_ns();
        prev->lat_release = prev->ts_last_release - prev->ts_last_acquire;
        bpf_get_current_comm(&prev->comm, sizeof(prev->comm));
        mmap_lock_release_events.perf_submit(args, prev, sizeof(*prev));
        mmap_lock_map.delete(&prev->key);
    }

    return 0;
}
"""

class mmap_lock_key_t(ctypes.Structure):
    _fields_ = [
        ('pid', ctypes.c_uint),
        ('tgid', ctypes.c_uint),
        ('is_write', ctypes.c_uint),
        ('mm', ctypes.c_void_p),
    ]

class mmap_lock_data_t(ctypes.Structure):
    _fields_ = [
        ('key', mmap_lock_key_t),
        ('n_attempts', ctypes.c_uint),
        ('ts_last_start', ctypes.c_ulong),
        ('ts_last_acquire', ctypes.c_ulong),
        ('ts_last_release', ctypes.c_ulong),
        ('lat_acquire', ctypes.c_ulong),
        ('lat_release', ctypes.c_ulong),
        ('comm', ctypes.c_char * 16),
    ]

parser = argparse.ArgumentParser(
            description="Trace mmap lock events and latency",
            formatter_class=argparse.RawDescriptionHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-a", action="store_true", default=False,
                   help="capture migrations across the system")
group.add_argument("-p", type=str, dest="progpath", metavar="PATH [ARGS]",
                   help="capture migrations for a given program")
args = parser.parse_args()

if os.geteuid() != 0:
    exit("You need root privileges to run this script")

def print_mmap_lock_release_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(mmap_lock_data_t)).contents
    print("%-16.16s %8s %8s %8s %10s %24.3f %24.3f" % (
          event.comm.decode("utf-8", "replace"),
          event.key.pid, event.key.tgid,
          "write" if event.key.is_write else "read", event.n_attempts,
          event.lat_acquire / 1000, event.lat_release / 1000))

b = BPF(text=bpf_text)
b["mmap_lock_release_events"].open_perf_buffer(print_mmap_lock_release_event,
                                               page_cnt=64)

print("%-16.16s %8s %8s %8s %10s %24s %24s" % (
      "COMM", "PID", "TGID", "TYPE", "ATTEMPTS",
      "ACQUIRE LATENCY (us)", "RELEASE LATENCY (us)"))

if args.progpath:
    p = subprocess.Popen(args.progpath.split(), shell=False,
                         stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    b["pid_map"][ctypes.c_uint(0)] = ctypes.c_uint(p.pid)

while True:
    try:
        b.perf_buffer_poll(500)
        if args.progpath is not None and p.poll() is not None:
            break
    except KeyboardInterrupt:
        if args.progpath:
            p.kill()
        break
