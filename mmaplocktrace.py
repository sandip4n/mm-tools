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

    unsigned int n_tries;
    unsigned int n_fails;

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
        data.n_tries = 1;
        mmap_lock_map.insert(&data.key, &data);
    } else if (prev->n_tries == prev->n_fails) {
        /* any previous attempts to acquire */
        prev->ts_last_start = bpf_ktime_get_ns();
        prev->n_tries++;
        mmap_lock_map.update(&prev->key, prev);
    } else {
        mmap_lock_anomaly_events.perf_submit(args, prev, sizeof(*prev));
        //mmap_lock_map.delete(&prev->key);
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
    if (!prev)
        return 0;

    if (prev->n_tries == (prev->n_fails + 1)) {
        /* any previous attempts to acquire */
        if (args->success) {
            prev->ts_last_acquire = bpf_ktime_get_ns();
            prev->lat_acquire += prev->ts_last_acquire - prev->ts_last_start;
            prev->lat_acquire /= prev->n_tries;
        } else {
            prev->n_fails++;
        }
        mmap_lock_map.update(&prev->key, prev);
    } else {
        //mmap_lock_anomaly_events.perf_submit(args, prev, sizeof(*prev));
        //mmap_lock_map.delete(&prev->key);
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
    if (!prev)
        return 0;

    if (prev->n_tries == (prev->n_fails + 1)) {
        /* any previous attempts to acquire */
        prev->ts_last_release = bpf_ktime_get_ns();
        prev->lat_release = prev->ts_last_release - prev->ts_last_acquire;
        bpf_get_current_comm(&prev->comm, sizeof(prev->comm));
        mmap_lock_release_events.perf_submit(args, prev, sizeof(*prev));
    } else {
        //mmap_lock_anomaly_events.perf_submit(args, prev, sizeof(*prev));
        //mmap_lock_map.delete(&prev->key);
    }

    mmap_lock_map.delete(&prev->key);
    return 0;
}
"""

parser = argparse.ArgumentParser(description="Trace mmap lock events and latency", formatter_class=argparse.RawDescriptionHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-a", action="store_true", default=False, help="capture migrations across the system")
group.add_argument("-p", type=str, dest="progpath", metavar="PATH [ARGS]", help="capture migrations for a given program")
args = parser.parse_args()

b = BPF(text=bpf_text)

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
        ('n_tries', ctypes.c_uint),
        ('n_fails', ctypes.c_uint),
        ('ts_last_start', ctypes.c_ulong),
        ('ts_last_acquire', ctypes.c_ulong),
        ('ts_last_release', ctypes.c_ulong),
        ('lat_acquire', ctypes.c_ulong),
        ('lat_release', ctypes.c_ulong),
        ('comm', ctypes.c_char * 16),
    ]

def print_mmap_lock_release_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(mmap_lock_data_t)).contents
    print("release: %-16.16s pid %-6s tgid %-6s %-8s tries %-8s fails %-8s latency (us) acquire %-10.3f release %-10.3f" % (
          event.comm.decode("utf-8", "replace"),
          event.key.pid, event.key.tgid,
          "write" if event.key.is_write else "read",
          event.n_tries, event.n_fails,
          event.lat_acquire / 1000, event.lat_release / 1000))

def print_mmap_lock_anomaly_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(mmap_lock_data_t)).contents
    error = "unknown error"
    if (event.ts_last_acquire > 0 and event.ts_last_release == 0):
        error = "attempt to re-acquire before release"
    print("anomaly: %-16.16s pid %-6s tgid %-6s mm %016x tries %-8s fails %-8s %s" % (
          event.comm.decode("utf-8", "replace"),
          event.key.pid, event.key.tgid, event.key.mm,
          event.n_tries, event.n_fails, error))

b["mmap_lock_release_events"].open_perf_buffer(print_mmap_lock_release_event, page_cnt=64)
b["mmap_lock_anomaly_events"].open_perf_buffer(print_mmap_lock_anomaly_event, page_cnt=64)

if args.progpath:
    p = subprocess.Popen(args.progpath.split(), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
