#!/usr/bin/python

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

#if !defined(CONFIG_PPC_BOOK3S_64) || !defined(CONFIG_SPARSEMEM_VMEMMAP)
#error "unsupported architecture"
#endif

BPF_ARRAY(pidmap, unsigned int);
BPF_HASH(cpumap, unsigned int, unsigned int);
BPF_PERF_OUTPUT(page_events);
BPF_PERF_OUTPUT(task_events);

struct page_migrate_data_t {
    unsigned int pid;
    unsigned long pfn;
    int orig_node;
    int dest_node;
    unsigned long ts;
    char comm[TASK_COMM_LEN];
};

struct task_migrate_data_t {
    unsigned int pid;
    int orig_node;
    int dest_node;
    unsigned long ts;
    char comm[TASK_COMM_LEN];
};

static inline int __page_to_node(struct page *page)
{
    unsigned long flags;
    bpf_probe_read_kernel(&flags, sizeof(flags), &(page->flags));
    return (flags >> NODES_PGSHIFT) & NODES_MASK;
}

static inline int __cpu_to_node(int cpu)
{
    int *node = cpumap.lookup(&cpu);
    if (!node)
        return -1;
    return *node;
}

static inline unsigned long __page_to_frame(struct page *page)
{
    /* vmemmap is virtually contiguous */
    return (unsigned long) ((unsigned long) page - 0xc00c000000000000UL);
}

static inline int __filter_pid(unsigned int pid)
{
    unsigned int zero = 0, *val;
    val = pidmap.lookup(&zero);
    return !(val && pid == *val);
}

int trace__migrate_misplaced_page(struct pt_regs *regs)
{
    struct page_migrate_data_t data = {};
    struct task_struct *task;
    struct page *page;

    page = (struct page *) PT_REGS_PARM1(regs);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *) bpf_get_current_task();

    if (__filter_pid(data.pid) && __filter_pid(task->real_parent->tgid))
        return 0;

    data.pfn = __page_to_frame(page);
    data.orig_node = __page_to_node(page);
    data.dest_node = PT_REGS_PARM3(regs);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts = bpf_ktime_get_ns();
    page_events.perf_submit(regs, &data, sizeof(data));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_migrate_task)
{
    struct task_migrate_data_t data = {};
    struct task_struct *task;

    data.pid = args->pid;
    task = (struct task_struct *) bpf_get_current_task();

    if (__filter_pid(data.pid) && __filter_pid(task->real_parent->tgid))
        return 0;

    data.orig_node = __cpu_to_node(args->orig_cpu);
    data.dest_node = __cpu_to_node(args->dest_cpu);

    /* check if this is a cross-node migration */
    if (data.orig_node >= 0 && data.dest_node >= 0 &&
        data.orig_node != data.dest_node) {
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.ts = bpf_ktime_get_ns();
        task_events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}
"""

parser = argparse.ArgumentParser(description="Trace page and task migrations", formatter_class=argparse.RawDescriptionHelpFormatter)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-a", action="store_true", default=False, help="capture migrations across the system")
group.add_argument("-p", type=str, dest="progpath", metavar="PATH [ARGS]", help="capture migrations for a given program")
args = parser.parse_args()

b = BPF(text=bpf_text)
b.attach_kprobe(event="migrate_misplaced_page", fn_name="trace__migrate_misplaced_page")

# determine node mapping for cpus
cpus = os.listdir("/sys/devices/system/cpu/")
cpus = [c for c in cpus if re.match(r'cpu\d+', c)]

for c in cpus:
    with open(os.path.join("/sys/devices/system/cpu", c, "topology", "physical_package_id")) as f:
        cpu = int(re.match(r'(cpu)(\d+)', c).group(2))
        node = int(f.read())
        b["cpumap"][ctypes.c_int(cpu)] = ctypes.c_int(node)

def print_page_event(cpu, data, size):
    event = b["page_events"].event(data)
    print("%016lu %-14.14s pid %-6s page with pfn %016lx migrated from node %s to %s" % (
            event.ts, event.comm.decode("utf-8", "replace"),
            event.pid, event.pfn, event.orig_node, event.dest_node))

def print_task_event(cpu, data, size):
    event = b["task_events"].event(data)
    print("%016lu %-14.14s pid %-6s task migrated from node %s to %s" % (
            event.ts, event.comm.decode("utf-8", "replace"),
            event.pid, event.orig_node, event.dest_node))

b["task_events"].open_perf_buffer(print_task_event, page_cnt=64)
b["page_events"].open_perf_buffer(print_page_event, page_cnt=64)

if args.progpath:
    p = subprocess.Popen(args.progpath.split(), shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b["pidmap"][ctypes.c_uint(0)] = ctypes.c_uint(p.pid)

while True:
    try:
        b.perf_buffer_poll(500)
        if args.progpath is not None and p.poll() is not None:
            break
    except KeyboardInterrupt:
        if args.progpath:
            p.kill()
        break
