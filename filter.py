from __future__ import print_function
from bcc import BPF
from netaddr import IPAddress

import ctypes as ct

# initialize BPF
b = BPF(src_file="filter.c", debug=0)

# struct data_t {
#     u32 saddr;
#     u32 daddr;
#     u16 sport;
#     u16 dport;
#     u8 type;
#     u8 fn;
# };
class Data(ct.Structure):
    _fields_ = [("saddr", ct.c_uint),
                ("daddr", ct.c_uint),
                ("sport", ct.c_ushort),
                ("dport", ct.c_ushort),
                ("type", ct.c_ubyte),
                ("fn", ct.c_ubyte)]

def format_ip(ip):
    str(IPAddress(ip))

def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%d %s:%d %s:%d %d" % (event.fn, format_ip(event.saddr), event.sport, format_ip(event.daddr), event.dport, event.type))

b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
