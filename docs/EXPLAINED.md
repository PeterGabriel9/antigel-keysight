# How the Network Emulator Works — Explained Simply

Imagine you are a postal worker inside a giant post office.
Trucks drop off packages (packets) at your door all day long.
Your job is to sort those packages, mess with some of them on purpose,
and then send them out the other door.

That is literally what this program does — but with network packets instead of boxes.

---

## The Big Picture

```
Internet packets come in
        |
        v
  [ We receive them ]
        |
        v
  [ We look at each one and decide which "pile" it belongs to ]
        |
        v
  [ We apply rules to that pile: throw some away, copy some, slow some down ]
        |
        v
  [ We send the survivors out ]
```

There are **two doors** (ports). One lcore (a CPU thread) handles each door.
- Thread 0 reads from door 0, sends out door 1.
- Thread 1 reads from door 1, sends out door 0.

They never talk to each other. They never share a notepad. Totally independent.

---

## What is a "packet"?

A packet is just a small chunk of data travelling over a network.
Think of it as an envelope. The envelope has:
- An **Ethernet header** — like the outside of the envelope (who sent it, to whom)
- An **IP header** — the city/street address
- A **TCP or UDP header** — the apartment number
- The actual **data** inside

In C, DPDK gives us each packet as a pointer called `struct rte_mbuf *m`.
It is just a struct that holds a pointer to the raw bytes of the envelope.

---

## Part 1 — Receiving packets (`rte_eth_rx_burst`)

```c
unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
```

This is like opening the mailbox and grabbing up to 32 envelopes at once.
`pkts_burst` is an array of 32 pointers, each pointing to one packet.
`nb_rx` tells us how many we actually got (could be 0 if nobody sent anything yet).

We do this in a loop forever until someone presses Ctrl+C.

---

## Part 2 — The 10 Sorting Piles (Profile Queues)

We have 10 piles on our desk. Every incoming packet goes into exactly one pile.
We call them **Profile Queues (PQ 0 through PQ 9)**.

The function that decides which pile is `classify_packet(m)`.
It returns a number from 0 to 9.

How does it decide? It peeks inside the envelope:

```
Is it an ICMP packet?          → pile 0  (like a ping, a "hello are you there?")
Is it going to port 80?        → pile 1  (HTTP, normal web traffic)
Is it going to port 443?       → pile 2  (HTTPS, secure web traffic)
Is it going to port 22?        → pile 3  (SSH, remote terminal)
Is it going to UDP port 53?    → pile 4  (DNS, "what is the address of google.com?")
Is it going to UDP port 123?   → pile 5  (NTP, clock synchronization)
Did it come from 10.0.0.x?     → pile 6  (a specific internal network)
Did it come from 192.168.0.x?  → pile 7  (another internal network)
TCP port under 1024 (other)?   → pile 8  (other important stuff)
Everything else                → pile 9  (default, nobody special)
```

Here is the actual C code that does the peeking:

```c
struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
```
`rte_pktmbuf_mtod` means "give me a pointer to the raw bytes of this packet,
but treat them as this struct type". So now `eth` points to the ethernet header.

Then we check if it is IPv4:
```c
if (rte_be_to_cpu_16(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
    return 9; // not IPv4, default pile
```
`rte_be_to_cpu_16` flips the bytes from network order to the CPU's order.
Networks store numbers with the big byte first. Your CPU stores them the opposite way.
This function fixes that so the number makes sense.

Then we look inside the IP header:
```c
struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
uint8_t proto  = ip->next_proto_id; // is it TCP, UDP, ICMP?
uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr); // who sent it?
```

`eth + 1` means "skip past the ethernet header, now point to the IP header".
In C, pointer arithmetic on a struct pointer moves by the size of the struct.
So `eth + 1` moves forward by exactly `sizeof(struct rte_ether_hdr)` bytes.

---

## Part 3 — The Rules for Each Pile

Each pile has three configurable rules:

| Rule | What it does |
|------|-------------|
| `drop_n` | Throw away N packets out of every 10 |
| `dup_n`  | Make a copy of N packets out of every 10, send both |
| `delay_us` | Hold packets for this many microseconds before sending |

These are all stored in `pq_configs`, a hardcoded array:

```c
static const struct pq_config pq_configs[NUM_PQ] = {
    [0] = { "ICMP",  drop_n=2, dup_n=0, delay_us=0    },
    [2] = { "HTTPS", drop_n=0, dup_n=0, delay_us=1000 },
    ...
};
```

The function `forward_mbuf()` applies these rules to one packet.

### Drop logic

```c
uint64_t count = pqs->pkt_count++;  // how many packets have we seen in this pile?

if (cfg->drop_n > 0 && (count % 10) < cfg->drop_n) {
    rte_pktmbuf_free(m);  // throw the envelope in the trash
    return;
}
```

`count % 10` gives us a number 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, ... repeating.
If `drop_n` is 2, we drop packets 0 and 1 out of every group of 10.
This is how we guarantee exactly N/10 drops regardless of burst size.

### Duplicate logic

```c
if (cfg->dup_n > 0 && (count % 10) < cfg->dup_n) {
    struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool, 0, UINT32_MAX);
    // send the clone
}
// then also send the original
```

`rte_pktmbuf_copy` makes a completely new independent copy of the packet,
like a photocopier for envelopes. We then put both in the outbox.

### Delay logic — the Waiting Room

This is the trickiest part. We cannot just `sleep()` because that would freeze
the whole thread and stop processing other packets.

Instead, we have a **waiting room** per pile: a circular array of slots.
Each slot holds a packet and the timestamp when it is allowed to leave.

```c
struct delay_entry {
    struct rte_mbuf *m;       // the packet sitting in the waiting room
    uint64_t release_tsc;     // the clock tick when it can leave
};
```

When a packet enters the waiting room:
```c
pqs->delay_q[pqs->dq_tail].m           = m;
pqs->delay_q[pqs->dq_tail].release_tsc = cur_tsc + delay_us * tsc_per_us;
pqs->dq_tail = (pqs->dq_tail + 1) % DELAY_QUEUE_SIZE; // move tail forward, wrap around
pqs->dq_count++;
```

The clock we use is `rte_rdtsc()` — it reads the CPU's internal tick counter.
It ticks billions of times per second, so we can measure microseconds easily.

`tsc_per_us` is how many ticks fit in one microsecond:
```c
uint64_t tsc_per_us = rte_get_tsc_hz() / 1000000;
```
`rte_get_tsc_hz()` = how many ticks per second. Divide by 1,000,000 → ticks per µs.

Every loop iteration we check if anyone in the waiting room can leave:
```c
while (pqs->dq_count > 0) {
    if (pqs->delay_q[pqs->dq_head].release_tsc > cur_tsc)
        break; // still waiting
    // time to go! send this packet
    struct rte_mbuf *m = pqs->delay_q[pqs->dq_head].m;
    pqs->dq_head = (pqs->dq_head + 1) % DELAY_QUEUE_SIZE;
    pqs->dq_count--;
    rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
}
```

We can `break` on the first packet that is still waiting because within one pile,
packets always enter in time order and all have the same delay. So if packet #5
is not ready, packets #6, #7, #8... definitely are not ready either.

---

## Part 4 — Sending packets (`rte_eth_tx_buffer` and `rte_eth_tx_buffer_flush`)

Sending one packet at a time is slow. So DPDK uses a **transmit buffer**: a small
waiting area on the send side. We add packets to it with:

```c
rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
```

When the buffer fills up (32 packets), DPDK sends them all in one go automatically.
Every 100 µs we also force-flush anything left in the buffer:

```c
rte_eth_tx_buffer_flush(tx_port_id, 0, tx_buffer[tx_port_id]);
```

---

## Part 5 — No Shared State = No Locks

This is the most important design choice.

Thread 0 has its own `lcore_states[0]` which contains 10 `pq_state` structs.
Thread 1 has its own `lcore_states[1]` which contains 10 `pq_state` structs.

They never touch each other's data. There is no mutex, no atomic, no lock.
This is safe because:
- Thread 0 only reads/writes `lcore_states[0]`
- Thread 1 only reads/writes `lcore_states[1]`
- They do write to `port_statistics[]` but that is only for display, small races there are harmless

```
  Thread 0 (lcore 0)          Thread 1 (lcore 1)
  ┌──────────────────┐        ┌──────────────────┐
  │ lcore_states[0]  │        │ lcore_states[1]  │
  │  pqs[0..9]       │        │  pqs[0..9]       │
  │  delay queues    │        │  delay queues    │
  └──────────────────┘        └──────────────────┘
         |                           |
    reads port 0               reads port 1
    writes port 1              writes port 0
         |                           |
    tx_buffer[1]               tx_buffer[0]
```

Because they write to **different** tx_buffers, even the send side has no conflict.

---

## The Main Loop — Everything Together

```c
while (!force_quit) {
    cur_tsc = rte_rdtsc();

    // 1. Release any delayed packets whose time has come
    flush_delay_queues(ls, tx_port_id, cur_tsc);

    // 2. Every 100 µs: flush TX buffer + maybe print stats
    if (cur_tsc - prev_tsc > drain_tsc) {
        rte_eth_tx_buffer_flush(...);
        print_stats();
        prev_tsc = cur_tsc;
    }

    // 3. Grab up to 32 new packets from the network
    nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);

    // 4. For each packet: classify → drop/dup/delay → send
    for (i = 0; i < nb_rx; i++) {
        pq_id = classify_packet(pkts_burst[i]);
        forward_mbuf(pkts_burst[i], pq_id, ...);
    }
}
```

Step 1 runs every single iteration so delayed packets escape as soon as their timer expires.
Step 3-4 runs only when packets actually arrive.

---

## Glossary (simple words for scary terms)

| Word | Simple meaning |
|------|----------------|
| `mbuf` | A struct that holds one packet (envelope) |
| `mempool` | A pre-allocated box of mbufs so we never call `malloc` during processing |
| `lcore` | A CPU thread pinned to one physical core |
| `TSC` | The CPU's internal nanosecond clock, read with one instruction |
| `tx_buffer` | A small staging area before actually sending packets |
| `rte_be_to_cpu_16/32` | Flip byte order: network sends big-byte-first, x86 wants small-byte-first |
| `port` | A network interface (a door packets come in or go out of) |
| Profile Queue | One of our 10 sorting piles, each with its own rules |
| Circular buffer | An array where the tail wraps back to the start when it reaches the end |
