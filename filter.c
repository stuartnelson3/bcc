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
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 type;
    u8 fn;
};

BPF_PERF_OUTPUT(events);

int kprobe__netif_receive_skb(struct pt_regs *ctx, struct __sk_buff *skb)
{
        /* stn_emit_event(ctx, skb, 1); */
        return 0;
};


int kprobe__ip_forward(struct pt_regs *ctx, struct sk_buff *skb)
{
        struct data_t d = {};

        void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_len;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);

        // Find start of tcp hdr by going through to offset.
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

        // The skb struct doesn't contain the tcp hdr.
        if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
                return 0;

        d.fn = 1;
        d.type = (*tcp).ack;
        d.saddr = ip->saddr;
        d.daddr = ip->daddr;
        d.sport = tcp->source;
        d.dport = tcp->dest;
        events.perf_submit(ctx, &d, sizeof(d));
        return 0;

        // Introspect skb for certain things (SYN/SYN-ACK, bond0, src/dst check)
        if (0 == (*tcp).syn)
                return 0;

        // Our network address for 10.144.0.0
        __be32 bm = 0x0a800000;
        // Netmask for first 16bit set
        __be32 nm = 0xff800000;

        // Checking that they belong to 10.144.0.0/16
        if (!((ip->saddr & nm) == bm && (ip->daddr & nm) == bm))
                return 0;

        // Must belong to different class-c networks
        __be32 dm = 0xffffff00;
        if ((ip->saddr & dm) == (ip->daddr & dm))
                return 0;


        // Make the struct
        d.fn = 2;
        d.type = (*tcp).ack;
        d.saddr = ip->saddr;
        d.daddr = ip->daddr;
        d.sport = tcp->source;
        d.dport = tcp->dest;

        // Send struct to user space
        events.perf_submit(ctx, &d, sizeof(d));
        return 0;
};
