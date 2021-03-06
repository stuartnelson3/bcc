#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/if_ether.h>

// Stuff we added.
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

#include <uapi/linux/bpf.h>

// define output data structure in C
struct data_t {
        s64 tstamp;
        u32 saddr;
        u32 daddr;
        u16 sport;
        u16 dport;
        u8 type;
        u8 fn;
};

BPF_PERF_OUTPUT(events);

static inline void filter_skb(uint fn, struct pt_regs *ctx, struct sk_buff *skb)
{
        struct data_t d = {};

        void *data = (void *)(long)skb->data;

        if (skb->data_len != 0)
                return;

        struct iphdr *ip = data;

        // Find start of tcp hdr by going through to offset.
        struct tcphdr *tcp = data + sizeof(*ip);

        if (skb->len < sizeof(*ip) + sizeof(*tcp))
                return;

        // Introspect skb for certain things (SYN/SYN-ACK, bond0, src/dst check)
        if (0 == (*tcp).syn)
                return;

        // Our network address for 10.144.0.0
        __be32 bm = 0x0000800a;
        // Netmask for first 16bit set
        __be32 nm = 0x000080ff;

        // Checking that they belong to 10.144.0.0/16
        if (!((ip->saddr & nm) == bm && (ip->daddr & nm) == bm))
                return;

        // Must belong to different class-c networks
        __be32 dm = 0x00ffffff;
        if ((ip->saddr & dm) == (ip->daddr & dm))
                return;

        // Make the struct
        d.fn = fn;
        d.type = (*tcp).ack;
        d.tstamp = bpf_ktime_get_ns() / 1000; // microsec
        d.saddr = ip->saddr;
        d.daddr = ip->daddr;
        d.sport = tcp->source;
        d.dport = tcp->dest;

        // Send struct to user space
        events.perf_submit(ctx, &d, sizeof(d));
}

int kprobe__netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
        filter_skb(10, ctx, skb);
        return 0;
};

int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
        filter_skb(20, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_forward.c?v=4.4#L78
int kprobe__ip_forward(struct pt_regs *ctx, struct sk_buff *skb)
{
        filter_skb(30, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_forward.c?v=4.4#L64
int kprobe__ip_forward_finish(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
        filter_skb(35, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_output.c?v=4.4#L349
int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
        filter_skb(40, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_output.c?v=4.4#L266
int kprobe__ip_finish_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
        filter_skb(50, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_output.c?v=4.4#L175
int kprobe__ip_finish_output2(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
        filter_skb(60, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/icmp.c?v-4.4#L568
int kprobe__icmp_send(struct pt_regs *ctx, struct sk_buff *skb, int type, int code, __be32 info)
{
        filter_skb(70, ctx, skb);
        return 0;
};

// http://lxr.free-electrons.com/source/net/ipv4/ip_input.c?v=4.4#L245
int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb)
{
        filter_skb(80, ctx, skb);
        return 0;
};
