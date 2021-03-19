#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import argparse
import ctypes
import os
import re
import time

prog = """
#include <linux/mm.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_HASH(cpumap, unsigned int, unsigned int);
BPF_PERF_OUTPUT(page_events);
BPF_PERF_OUTPUT(task_events);

struct page_migrate_data_t {
    unsigned int pid;
    int orig_node;
    int dest_node;
    char comm[TASK_COMM_LEN];
};

struct task_migrate_data_t {
    unsigned int pid;
    int orig_node;
    int dest_node;
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

int trace__migrate_misplaced_page(struct pt_regs *regs)
{
    struct page_migrate_data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.orig_node = __page_to_node((struct page *) PT_REGS_PARM1(regs));
    data.dest_node = PT_REGS_PARM3(regs);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    page_events.perf_submit(regs, &data, sizeof(data));

    return 0;
}

TRACEPOINT_PROBE(sched, sched_migrate_task)
{
    struct task_migrate_data_t data = {};

    data.pid = args->pid;
    data.orig_node = __cpu_to_node(args->orig_cpu);
    data.dest_node = __cpu_to_node(args->dest_cpu);

    /* check if this is a cross-node migration */
    if (data.orig_node >= 0 && data.dest_node >= 0 &&
        data.orig_node != data.dest_node) {
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        task_events.perf_submit(args, &data, sizeof(data));
    }

    return 0;
}
"""

b = BPF(text=prog)
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
    event = b["task_events"].event(data)
    print("%-14.14s pid %-6s page migrated from node %s to %s" % (
            event.comm.decode("utf-8", "replace"),
            event.pid, event.orig_node, event.dest_node))

def print_task_event(cpu, data, size):
    event = b["task_events"].event(data)
    print("%-14.14s pid %-6s task migrated from node %s to %s" % (
            event.comm.decode("utf-8", "replace"),
            event.pid, event.orig_node, event.dest_node))

b["task_events"].open_perf_buffer(print_task_event, page_cnt=512)
b["page_events"].open_perf_buffer(print_page_event, page_cnt=512)

while True:
    try:
        b.perf_buffer_poll()
        time.sleep(0.5)
    except KeyboardInterrupt:
        exit()
