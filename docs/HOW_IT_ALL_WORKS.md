# How the Whole Thing Works — My Notes

---

## The Problem

So basically the whole point of this project is to simulate a bad network.
Real networks drop packets, delay them, duplicate them — and we want to reproduce that
in a controlled way so you can test how your application behaves when the network is terrible.

The hard part is doing this FAST. We are talking millions of packets per second.
A normal Linux program cannot do that because the kernel gets in the way.
That is where DPDK comes in.

---

## Why DPDK

Normally when a packet arrives at your network card, this happens:

```
packet arrives at NIC
    → NIC interrupts the CPU ("hey I have data!")
    → kernel wakes up
    → kernel copies packet from NIC memory into kernel memory
    → kernel copies packet from kernel memory into your program
    → your program finally sees it
```

That is two copies and one interrupt per packet. At 10 million packets/second that is
10 million interrupts/second. The CPU spends all its time just handling interrupts
and copying memory — no time left for actual work.

DPDK fixes this by completely bypassing the kernel:

```
packet arrives at NIC
    → NIC writes it directly into memory your program owns (DMA)
    → your program reads it directly
```

No interrupt. No copy. No kernel. Just your code talking directly to the hardware.

The trade-off is that DPDK "steals" a whole CPU core and runs it in a tight infinite loop
constantly checking "did anything arrive?" — this is called **poll mode**.
It wastes power but latency drops massively and throughput goes through the roof.

---

## HugePages

Quick thing about memory. CPUs have a small cache called the TLB that remembers
"virtual address X lives at physical address Y". It is tiny, maybe 1024 entries.

With normal 4KB pages you can cache 4MB of address mappings.
With 2MB HugePages you cache 2GB. Way fewer cache misses, way faster.

In our case we use `--no-huge` because we test with fake (pcap) devices.
On real hardware with real NICs you absolutely need HugePages.

---

## DPDK Building Blocks

### The Memory Pool (mempool)

Calling malloc() for every single packet would be way too slow.
So at startup we pre-allocate a big pool of fixed-size buffers.

```c
#define NB_MBUFS_MIN    8192U
#define EXTRA_MBUFS     (NB_PORTS * NUM_PQ * DELAY_QUEUE_SIZE * 2)

netem_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
    RTE_MAX(nb_mbufs, NB_MBUFS_MIN) + EXTRA_MBUFS, ...);
```

When a packet arrives DPDK grabs one buffer from the pool instantly.
When we're done with a packet `rte_pktmbuf_free(m)` just puts it back — not an actual free().
Think of it like borrowing a glass from a kitchen and putting it back in the cabinet.

### The mbuf

An mbuf (memory buffer) is the struct that wraps one packet.

```c
struct rte_mbuf *m;

/* get a pointer to the raw packet bytes, cast to ethernet header */
#define PKT_ETH(m) rte_pktmbuf_mtod((m), struct rte_ether_hdr *)

/* get a pointer to the IP header (right after ethernet) */
#define PKT_IP(m)  ((struct rte_ipv4_hdr *)(PKT_ETH(m) + 1))
```

`rte_pktmbuf_mtod` literally means "mbuf to data" — gives you a raw pointer to the bytes.
The cast to a struct type lets you read fields by name instead of doing manual byte arithmetic.

### RX and TX Rings

The NIC has two circular arrays in memory:
- **RX ring** — NIC drops incoming packets here
- **TX ring** — you put outgoing packets here, NIC sends them

Circular means when you hit the end you wrap back to index 0:

```c
#define RING_NEXT(idx, size) (((idx) + 1) % (size))

/* used in our delay queue */
pqs->dq_tail = RING_NEXT(pqs->dq_tail, DELAY_QUEUE_SIZE);
```

### Burst Processing

Reading 32 packets per call is way more efficient than 1 at a time.
The function call overhead is paid once for 32 packets instead of 32 times.

```c
#define MAX_PKT_BURST 32

struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
```

`nb_rx` is how many actually arrived (could be less than 32, could be 0).

### TX Buffer

Same idea on the send side. We accumulate packets and send them in bulk.

```c
#define BURST_TX_DRAIN_US 100  /* flush TX buffer every 100 microseconds */

/* add packet to outgoing buffer */
rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);

/* force send everything that is waiting */
rte_eth_tx_buffer_flush(tx_port_id, 0, tx_buffer[tx_port_id]);
```

---

## Virtual Devices (how we test without real hardware)

Real DPDK needs special 10/25/100 Gbps Intel or Mellanox network cards.
We do not have that so we use the `net_pcap` driver — a software NIC that reads/writes .pcap files.

```bash
--vdev 'net_pcap0,rx_pcap=/home/student/input.pcap,infinite_rx=0'
--vdev 'net_pcap1,tx_pcap=/home/student/output.pcap'
```

Port 0 acts like a NIC receiving traffic from `input.pcap`.
Port 1 acts like a NIC that "sends" packets — but really writes them to `output.pcap`.

After running you open `output.pcap` in Wireshark and see what survived.

---

## Our Application — Step By Step

### Startup

```c
rte_eal_init(argc, argv);        /* DPDK startup: grab cores, setup memory */
rte_pktmbuf_pool_create(...);    /* pre-allocate all packet buffers */
rte_eth_dev_configure(...);      /* set up each port */
rte_eth_rx_queue_setup(...);     /* connect RX ring to our mempool */
rte_eth_tx_queue_setup(...);     /* set up TX ring */
rte_eth_dev_start(...);          /* ports are now live */
rte_eal_mp_remote_launch(...);   /* start main loop on both CPU cores */
```

### The Main Loop

```c
while (!force_quit) {
    uint64_t cur_tsc = rte_rdtsc();   /* read CPU clock */

    flush_delay_queues(ls, tx_port_id, cur_tsc);   /* release any ready packets */

    if (cur_tsc - prev_tsc > drain_tsc) {   /* every 100us */
        rte_eth_tx_buffer_flush(...);
        if (timer_tsc >= timer_period)       /* every 1 second */
            print_stats();
        prev_tsc = cur_tsc;
    }

    unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
    if (nb_rx == 0) continue;

    for (unsigned i = 0; i < nb_rx; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *)); /* load into cache early */
        uint16_t pq = classify_packet(pkts_burst[i]);
        forward_mbuf(pkts_burst[i], pq, ...);
    }
}
```

The loop runs millions of times per second. No sleep, no blocking, no waiting.

---

## Packet Classification

When a packet arrives we peek at its headers and decide which of the 10 Profile Queues
it belongs to. First match wins.

```c
/* protocol numbers (from IP header next_proto_id field) */
#define PROTO_ICMP  1
#define PROTO_TCP   6
#define PROTO_UDP  17

/* well-known TCP ports */
#define PORT_HTTP   80
#define PORT_HTTPS 443
#define PORT_SSH    22
#define PORT_DNS    53
#define PORT_NTP   123
#define PORT_WELLKNOWN_MAX 1024

/* IP prefix matching — mask off the last octet and compare */
#define IP_IN_SLASH24(ip, prefix_24bit) (((ip) >> 8) == ((prefix_24bit) >> 8))

#define NET_10_0_0      0x0A000000   /* 10.0.0.0  */
#define NET_192_168_0   0xC0A80000   /* 192.168.0.0 */
```

```c
static uint16_t
classify_packet(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = PKT_ETH(m);
    if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
        return 9;

    struct rte_ipv4_hdr *ip = PKT_IP(m);
    uint8_t  proto  = ip->next_proto_id;
    uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
    uint32_t ihl    = (ip->version_ihl & 0x0f) * 4;

    if (proto == PROTO_ICMP)                     return 0;
    if (IP_IN_SLASH24(src_ip, NET_10_0_0))       return 6;
    if (IP_IN_SLASH24(src_ip, NET_192_168_0))    return 7;

    /* get pointer to TCP or UDP header (right after IP header) */
    uint8_t *l4 = (uint8_t *)ip + ihl;

    if (proto == PROTO_TCP) {
        uint16_t dport = rte_be_to_cpu_16(((struct rte_tcp_hdr *)l4)->dst_port);
        if (dport == PORT_HTTP)              return 1;
        if (dport == PORT_HTTPS)             return 2;
        if (dport == PORT_SSH)               return 3;
        if (dport <  PORT_WELLKNOWN_MAX)     return 8;
        return 9;
    }
    if (proto == PROTO_UDP) {
        uint16_t dport = rte_be_to_cpu_16(((struct rte_udp_hdr *)l4)->dst_port);
        if (dport == PORT_DNS)               return 4;
        if (dport == PORT_NTP)               return 5;
        return 9;
    }
    return 9;
}
```

**Byte order note:** The network sends numbers most-significant-byte first (big-endian).
Your x86 CPU is little-endian (least significant byte first). So every number we read
from a packet header must be byte-swapped. `rte_be_to_cpu_16/32` does that.
Forget this and all your port comparisons will be silently wrong.

---

## The Three Behaviors

### Drop

```c
#define PACKETS_PER_GROUP 10

/* should we drop packet number `count` given that we drop `drop_n` per group? */
#define SHOULD_DROP(count, drop_n) ((drop_n) > 0 && ((count) % PACKETS_PER_GROUP) < (drop_n))

if (SHOULD_DROP(count, cfg->drop_n)) {
    rte_pktmbuf_free(m);          /* return buffer to pool */
    port_statistics[rx].dropped++;
    return;
}
```

`pkt_count` is a counter that never resets — it tracks every packet this PQ has ever seen.
`count % 10` cycles 0,1,2,...,9,0,1,2,...

If `drop_n = 2` we drop when count%10 is 0 or 1 — that is exactly 2 out of every 10.

The key thing is counting across bursts. The original code used the burst index `i`:
```c
/* WRONG — broken across bursts */
if (i % 10 == 5) { ... }
```
If a burst has 7 packets, `i` goes 0-6 and we never hit 5 in some bursts.
Our running `pkt_count` solves this — it doesn't care about burst boundaries.

### Duplicate

```c
#define SHOULD_DUP(count, dup_n) ((dup_n) > 0 && ((count) % PACKETS_PER_GROUP) < (dup_n))

if (SHOULD_DUP(count, cfg->dup_n)) {
    struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool, 0, UINT32_MAX);
    if (clone)
        send_or_delay(clone, cfg, pqs, tx_port_id, cur_tsc, tsc_per_us);
}
/* always send the original too */
send_or_delay(m, cfg, pqs, tx_port_id, cur_tsc, tsc_per_us);
```

`rte_pktmbuf_copy` grabs a fresh buffer from the pool and copies all bytes into it.
Now we have two independent mbufs with identical contents. Both get forwarded.

### Delay — The Waiting Room

This is the interesting one. We can not sleep because that blocks the whole thread.

Instead we have a ring buffer per PQ where packets sit until their timer expires.

```c
#define DELAY_QUEUE_SIZE  2048
#define RING_NEXT(i, sz)  (((i) + 1) % (sz))

struct delay_entry {
    struct rte_mbuf *m;
    uint64_t         release_tsc;
};
```

The timer is the CPU's TSC register — a counter that ticks billions of times per second.

```c
/* how many TSC ticks fit in 1 microsecond */
#define TSC_PER_US(hz)  ((hz) / 1000000ULL)

uint64_t tsc_per_us = TSC_PER_US(rte_get_tsc_hz());
/* on a 3.2GHz CPU: 3200000000 / 1000000 = 3200 ticks per microsecond */
```

Enqueuing a packet for delay:
```c
static inline void
delay_enqueue(struct pq_state *pqs, struct rte_mbuf *m, uint64_t release_tsc)
{
    if (pqs->dq_count >= DELAY_QUEUE_SIZE) {
        rte_pktmbuf_free(m);   /* overflow protection — drop rather than crash */
        return;
    }
    pqs->delay_q[pqs->dq_tail].m           = m;
    pqs->delay_q[pqs->dq_tail].release_tsc = release_tsc;
    pqs->dq_tail  = RING_NEXT(pqs->dq_tail, DELAY_QUEUE_SIZE);
    pqs->dq_count++;
}
```

Releasing packets every loop iteration:
```c
static void
flush_delay_queues(struct lcore_state *ls, uint16_t tx_port_id, uint64_t cur_tsc)
{
    for (int pq = 0; pq < NUM_PQ; pq++) {
        struct pq_state *pqs = &ls->pqs[pq];
        while (pqs->dq_count > 0) {
            if (pqs->delay_q[pqs->dq_head].release_tsc > cur_tsc)
                break;   /* still waiting; all packets behind this are also waiting */
            struct rte_mbuf *m = pqs->delay_q[pqs->dq_head].m;
            pqs->dq_head = RING_NEXT(pqs->dq_head, DELAY_QUEUE_SIZE);
            pqs->dq_count--;
            rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
        }
    }
}
```

The `break` works because within one PQ all packets have the same delay and arrive in
time order, so `release_tsc` values are monotonically increasing from head to tail.
If the head isn't ready, nothing behind it is ready either.

---

## Parallelism

### Two Threads, Two Ports

```
lcore 0: reads port 0  →  writes port 1
lcore 1: reads port 1  →  writes port 0
```

Each thread is pinned to its own physical CPU core by DPDK's EAL.
They run simultaneously and never wait for each other.

### No Locks — Ever

Locks (mutexes) make one thread wait for another. At millions of packets/second
even a few microseconds of waiting = thousands of dropped packets. We avoid all locks.

The trick: each thread has completely private state.

```c
struct lcore_state {
    struct pq_state pqs[NUM_PQ];   /* 10 queues, each with their own delay ring */
} __rte_cache_aligned;

static struct lcore_state lcore_states[RTE_MAX_LCORE];
```

Thread 0 only reads/writes `lcore_states[0]`.
Thread 1 only reads/writes `lcore_states[1]`.
No overlap. No lock needed. No race condition possible.

The TX buffers also don't overlap:
- Thread 0 → `tx_buffer[1]`
- Thread 1 → `tx_buffer[0]`

### False Sharing and Cache Alignment

CPUs load memory in 64-byte chunks called cache lines.
If two threads have variables in the same cache line, every write by thread 0
forces thread 1 to reload the whole 64 bytes — this is called false sharing and
it silently destroys performance even though neither thread is actually reading
the other's variable.

`__rte_cache_aligned` tells the compiler to put the struct at a 64-byte boundary
so its data occupies its own cache lines, never shared with another thread's data.

### Prefetch

```c
rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
```

Before we process packet `i`, we tell the CPU to start loading packet `i`'s data
from RAM into the L1 cache now, in the background, while the CPU handles other work.
By the time we get to `i`, the data is already warm in cache — no stall waiting for RAM.

---

## The Stats

Every 1 second the main lcore prints rx/tx/drop/dup/delay counts.

```c
#define STATS_PERIOD_SEC 1ULL

timer_period = STATS_PERIOD_SEC * rte_get_timer_hz();

timer_tsc += cur_tsc - prev_tsc;
if (timer_tsc >= timer_period) {
    print_stats();
    timer_tsc = 0;
}
```

`rte_get_timer_hz()` returns ticks per second. Multiplied by 1 gives us the tick
count for 1 second. When accumulated TSC delta exceeds that, one second has passed.

---

## End-to-End Flow

```
input.pcap
    │  (pcap NIC driver replays packets as if from wire)
    ▼
Port 0 RX ring
    │  rte_eth_rx_burst() — grab 32 at a time
    ▼
pkts_burst[]
    │  classify_packet() — peek at headers
    ▼
PQ 0-9
    │  forward_mbuf() — apply rules
    │
    ├── DROP?   → rte_pktmbuf_free()   (buffer back to pool)
    │
    ├── DUP?    → rte_pktmbuf_copy()   (clone goes same path as original)
    │
    └── DELAY?  → delay_q[pq]          (sit here until release_tsc passes)
        or
        SEND    → rte_eth_tx_buffer()  (accumulate until buffer full or 100µs)
                        │
                        ▼
                  Port 1 TX ring
                        │  (pcap driver writes to file)
                        ▼
                  output.pcap
```

---

## Common Questions

**Why not use raw sockets?**
Raw sockets still go through the kernel. Syscall overhead + interrupt per packet.
At 10M pps that is 10M syscalls/second. DPDK avoids all of that.

**How precise is the delay?**
Sub-microsecond. TSC ticks billions of times per second and we check the delay
queue on every main loop iteration (also millions of times/second).

**What if the delay queue fills up (2048 slots)?**
The new packet is dropped (`rte_pktmbuf_free`) rather than crashing.
Graceful degradation under extreme load.

**Why is the drop counted across bursts and not per burst?**
A burst can have 1 to 32 packets. If we count within the burst, a burst of 7 packets
never sees positions 7-9, so the drop ratio drifts. The persistent `pkt_count`
counter sees every packet ever received by that PQ regardless of burst size.

**Why circular buffer for the delay queue?**
O(1) enqueue, O(1) dequeue, no allocation, no fragmentation, cache-friendly.
And because all packets in one PQ have the same delay, the ring is always sorted
by release_tsc so we can stop at the first unexpired entry.
