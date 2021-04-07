#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import argparse
import time

bpf_text = """
#include <linux/mmzone.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 2048);

struct trace_data_t {
    unsigned int pid;
    unsigned int tid;
    unsigned int nid;
    int kern_stack_id;
    int user_stack_id;
    int anon_active;
    int anon_inactive;
    int file_active;
    int file_inactive;
    char comm[TASK_COMM_LEN];
};

int trace__mod_lruvec_state(struct pt_regs *regs)
{
    struct lruvec *lruvec = (void *) PT_REGS_PARM1(regs);
    enum node_stat_item idx = PT_REGS_PARM2(regs);
    int val = PT_REGS_PARM3(regs);

    struct trace_data_t data = {};
    unsigned long ts = bpf_ktime_get_ns();
    unsigned long id = bpf_get_current_pid_tgid();

    data.pid = id >> 32;
    data.tid = id;
    data.nid = lruvec->pgdat->node_id;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (idx == NR_ACTIVE_ANON)
        data.anon_active = val;
    else if (idx == NR_INACTIVE_ANON)
        data.anon_inactive = val;
    else if (idx == NR_ACTIVE_FILE)
        data.file_active = val;
    else if (idx == NR_INACTIVE_FILE)
        data.file_inactive = val;
    else
        goto done;

    data.kern_stack_id = stack_traces.get_stackid(regs, BPF_F_REUSE_STACKID);
    data.user_stack_id = stack_traces.get_stackid(regs, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
    events.perf_submit(regs, &data, sizeof(data));

done:
    return 0;
}
"""

parser = argparse.ArgumentParser(description="Trace LRU page activity", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("--anon-active", action="store_true", default=False, help="capture active anon page actvity")
parser.add_argument("--anon-inactive", action="store_true", default=False, help="capture inactive anon page actvity")
parser.add_argument("--file-active", action="store_true", default=False, help="capture active file page actvity")
parser.add_argument("--file-inactive", action="store_true", default=False, help="capture inactive file page actvity")
args = parser.parse_args()

if not any(vars(args).values()):
    parser.error("one of the arguments --anon-active --anon-inactive --file-active --file-inactive is required")

b = BPF(text=bpf_text)
b.attach_kprobe(event="__mod_lruvec_state", fn_name="trace__mod_lruvec_state")
stack_traces = b["stack_traces"]

def print_event(cpu, data, size):
    event = b["events"].event(data)
    event_name = ""
    event_diff = ""

    if args.anon_active and event.anon_active:
        event_name = "anon-active"
        event_diff = event.anon_active
    elif args.anon_inactive and event.anon_inactive:
        event_name = "anon-inactive"
        event_diff = event.anon_inactive
    elif args.file_active and event.file_active:
        event_name = "file-active"
        event_diff = event.file_active
    elif args.file_inactive and event.file_inactive:
        event_name = "file-inactive"
        event_diff = event.file_inactive
    else:
        return

    print("%-14.14s %-6s %-4s %-20s %-4s" % (event.comm.decode("utf-8", "replace"), event.pid, event.nid, event_name, event_diff))

    for addr in stack_traces.walk(event.kern_stack_id):
        sym = b.ksym(addr, show_offset=True)
        print("\t%s" % sym.decode())

    if event.user_stack_id > 0:
        for addr in stack_traces.walk(event.user_stack_id):
            sym = b.sym(addr, event.pid, show_module=True, show_offset=True)
            print("\t%s" % sym.decode())

    print("")

b["events"].open_perf_buffer(print_event, page_cnt=512)
while True:
    try:
        b.perf_buffer_poll()
        time.sleep(0.5)
    except KeyboardInterrupt:
        exit()
