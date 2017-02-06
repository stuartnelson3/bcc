from __future__ import print_function
from bcc import BPF
from netaddr import IPAddress

import ctypes as ct

from socket import ntohs, ntohl

# initialize BPF
b = BPF(src_file="filter.c", debug=0)

# struct data_t {
#         s64 tstamp;
#         u32 saddr;
#         u32 daddr;
#         u16 sport;
#         u16 dport;
#         u8 type;
#         u8 fn;
# };
class Data(ct.Structure):
    _fields_ = [("tstamp", ct.c_longlong),
                ("saddr", ct.c_uint),
                ("daddr", ct.c_uint),
                ("sport", ct.c_ushort),
                ("dport", ct.c_ushort),
                ("type", ct.c_ubyte),
                ("fn", ct.c_ubyte)]

def format_ip(ip):
    return str(IPAddress(ntohl(ip)))

def print_event(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print("%d %d %s:%d %s:%d %d" %
            (event.tstamp, event.fn, format_ip(event.saddr), ntohs(event.sport), format_ip(event.daddr), ntohs(event.dport), event.type))

def fn_to_name(fn):
    dictionary = {10 : 'netif_receive_skb',
            20 : 'ip_rcv',
            30 : 'ip_forward',
            35 : 'ip_forward_finish',
            40 : 'ip_output',
            50 : 'ip_finish_output',
            60 : 'ip_finish_output2',
            70 : 'icmp_send',
            80 : 'ip_local_deliver'}
    return dictionary[fn]

b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
