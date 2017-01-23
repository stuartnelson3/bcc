from bcc import BPF

import sys

kernel_fn=sys.argv[1]

if not kernel_fn:
    sys.exit("usage: counter.py <kernel_function>")

# BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()

prog = """
int counter(void *ctx) {
    bpf_trace_printk("1 \\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
print("instrumenting function %s" % kernel_fn)
# Replace sys_clone with appropriate function name
b.attach_kprobe(event=kernel_fn, fn_name="counter")

# header
# print("%-18s %-16s %-6s %s" % ("TIME(s)", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %s %s" % (ts, kernel_fn, msg))
