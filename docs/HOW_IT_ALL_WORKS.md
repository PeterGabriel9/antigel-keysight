# How the Whole Thing Works — My Notes
(si de ce am luat deciziile pe care le-am luat)

---

## The Problem

So basically the whole point of this project is to simulate a bad network.
Real networks drop packets, delay them, duplicate them — si vrem sa reproducem asta
in mod controlat ca sa putem testa cum se comporta o aplicatie cand reteaua e proasta.

The hard part is doing this FAST. We are talking millions of packets per second.
A normal Linux program cannot do that because the kernel gets in the way.
That is where DPDK comes in.

---

## De ce DPDK?

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
10 million interrupts/second. CPU-ul isi petrece tot timpul gestionand intreruperi
si copiind memorie — nu mai ramane timp pentru treaba utila.

DPDK fixes this by bypassing the kernel completely:

```
packet arrives at NIC
    → NIC writes it directly into memory your program owns (DMA)
    → your program reads it directly
```

No interrupt. No copy. No kernel. Just your code talking directly to the hardware.

Trade-off-ul e ca DPDK "fura" un CPU core intreg si il tine intr-o bucla infinita
care verifica constant "a venit ceva?" — asta se numeste **poll mode**.
Consuma mai mult curent dar latenta scade enorm si throughput-ul creste mult.

---

## HugePages

O chestie rapida despre memorie. CPU-urile au un cache mic numit TLB care retine
mapari de tipul "virtual address X se afla la physical address Y".
E mic, maybe 1024 entries.

With normal 4KB pages you can cache 4MB of address mappings.
With 2MB HugePages you cache 2GB. Way fewer cache misses, way faster.

In cazul nostru folosim `--no-huge` pentru ca testam cu dispozitive virtuale (pcap).
Pe hardware real cu NICs reale ai nevoie absolut de HugePages.

---

## DPDK Building Blocks

### Memory Pool (mempool)

Calling malloc() for every single packet ar fi mult prea lent.
So at startup we pre-allocate a big pool of fixed-size buffers:

```c
netem_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
    MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
```

When a packet arrives, DPDK grabs one buffer from pool instantly.
When we're done with a packet, `rte_pktmbuf_free(m)` just puts it back — not an actual free().
E ca si cum imprumuti un pahar din bucatarie si il pui inapoi in dulap.

### The mbuf

An mbuf (memory buffer) is the struct that wraps one packet:

```c
struct rte_mbuf *m;

// get a pointer to the raw packet bytes, cast to ethernet header
#define PKT_ETH(m) rte_pktmbuf_mtod((m), struct rte_ether_hdr *)

// get a pointer to the IP header (right after ethernet)
#define PKT_IP(m)  ((struct rte_ipv4_hdr *)(PKT_ETH(m) + 1))
```

`rte_pktmbuf_mtod` means "mbuf to data" — gives you a raw pointer to the bytes.
Cast-ul la un tip struct iti permite sa citesti campuri dupa nume in loc sa faci
aritmetica manuala pe bytes.

### RX si TX Rings

NIC-ul are doua array-uri circulare in memorie:
- **RX ring** — NIC pune pachetele primite aici
- **TX ring** — tu pui pachetele de trimis, NIC le trimite

Circular means when you hit the end you wrap back to index 0:

```c
#define RING_NEXT(idx, size) (((idx) + 1) % (size))

// folosit in delay queue-ul nostru
pqs->dq_tail = RING_NEXT(pqs->dq_tail, DELAY_QUEUE_SIZE);
```

### Burst Processing

Reading 32 packets per call is way more efficient than one at a time.
The function call overhead is paid once for 32 packets instead of 32 times separately.

```c
#define MAX_PKT_BURST 32

struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
```

`nb_rx` is how many actually arrived — can be less than 32, can be 0.

### TX Buffer

Same idea on the send side. We accumulate packets and send them in bulk:

```c
#define BURST_TX_DRAIN_US 100  // flush TX buffer every 100 microseconds

// add packet to outgoing buffer
rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);

// force send everything that is waiting
rte_eth_tx_buffer_flush(tx_port_id, 0, tx_buffer[tx_port_id]);
```

---

## Virtual Devices (cum testam fara hardware real)

Real DPDK needs special 10/25/100 Gbps network cards (Intel, Mellanox etc).
Noi n-avem asa ceva, asa ca folosim driverul `net_pcap` — un NIC software care
citeste/scrie fisiere .pcap:

```bash
--vdev 'net_pcap0,rx_pcap=/home/student/input.pcap,infinite_rx=0'
--vdev 'net_pcap1,tx_pcap=/home/student/output.pcap'
```

Port 0 se comporta ca un NIC care primeste trafic din `input.pcap`.
Port 1 se comporta ca un NIC care "trimite" pachete — dar de fapt le scrie in `output.pcap`.

After running, you open `output.pcap` in Wireshark and see what survived.

---

## Our Application — Step By Step

### Startup

```c
rte_eal_init(argc, argv);        // DPDK startup: grab cores, setup memory
rte_pktmbuf_pool_create(...);    // pre-allocate all packet buffers
rte_eth_dev_configure(...);      // set up each port
rte_eth_rx_queue_setup(...);     // connect RX ring to our mempool
rte_eth_tx_queue_setup(...);     // set up TX ring
rte_eth_dev_start(...);          // ports are now live
http_server_start(HTTP_PORT);    // start dashboard server
rte_eal_mp_remote_launch(...);   // start main loop on both CPU cores
```

### Main Loop

```c
while (!force_quit) {
    uint64_t cur_tsc = rte_rdtsc();   // read CPU clock

    flush_delay_queues(ls, tx_port_id, cur_tsc);   // release any ready packets

    if (cur_tsc - prev_tsc > drain_tsc) {   // every ~100us
        rte_eth_tx_buffer_flush(...);
        if (timer_tsc >= timer_period)       // every 1 second
            print_stats();
        prev_tsc = cur_tsc;
    }

    unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
    if (nb_rx == 0) continue;

    for (unsigned i = 0; i < nb_rx; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
        process_packet(pkts_burst[i], rx_port_id, tx_port_id, ls, cur_tsc, tsc_per_us);
    }
}
```

The loop runs millions of times per second. No sleep, no blocking, no waiting for anything.

---

## Clasificarea pachetelor

When a packet arrives we look inside its payload and decide which of the 10 Profile Queues
it belongs to. First match wins.

Nu folosim numerele de port — porturile pot minti. Oricine poate rula SSH pe portul 80.
In schimb ne uitam la primii bytes din payload si cautam pattern-uri cunoscute:

```c
// HTTP: request methods and response prefix
#define IS_HTTP(buf, len) (
    PAYLOAD_STARTS_WITH(buf, len, "GET ",  4) || ...

// TLS: record header always starts with content_type(0x14-0x17) + 0x03 + minor_ver
#define IS_TLS(buf, len) (
    (len) >= 3 && (buf)[0] >= 0x14 && (buf)[0] <= 0x17 && (buf)[1] == 0x03 ...

// SSH: RFC says both sides must open with "SSH-"
#define IS_SSH(buf, len) PAYLOAD_STARTS_WITH(buf, len, "SSH-", 4)
```

**Nota despre byte order:** Network-ul trimite numere cu byte-ul cel mai semnificativ primul (big-endian).
x86 e little-endian (byte-ul cel mai putin semnificativ primul). So every number we read
from a packet header must be byte-swapped. `rte_be_to_cpu_16/32` does that for us.
Daca uiti asta toate comparatiile tale de adrese/porturi vor fi gresite si nu vei stii de ce.

---

## The Three Behaviors

### Drop

```c
#define SHOULD_DROP(count, drop_n) ((drop_n) > 0 && ((count) % PACKETS_PER_GROUP) < (drop_n))

if (SHOULD_DROP(count, cfg->drop_n)) {
    rte_pktmbuf_free(m);  // return buffer back to pool
    port_statistics[rx_port_id].dropped++;
    return;
}
```

`pkt_count` e un counter care nu se reseteaza — urmareste fiecare pachet vazut vreodata de PQ-ul asta.
`count % 10` cicleaza 0,1,2,...,9,0,1,2,...

If `drop_n = 2` we drop when count%10 is 0 or 1 — that is exactly 2 out of every 10.

Important: numaram cross-burst. Original code used burst index `i` which is wrong:
```c
// GRESIT — se strica pe burst boundaries
if (i % 10 == 5) { ... }
```
Daca un burst are 7 pachete, `i` merge 0-6 si pozitia 7, 8, 9 nu se vede in acel burst.
Cu `pkt_count` persistent n-avem problema asta.

### Duplicate

```c
if (SHOULD_DUP(count, cfg->dup_n)) {
    struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool, 0, UINT32_MAX);
    if (clone != NULL) {
        if (cfg->delay_us > 0)
            delay_enqueue(pqs, clone, RELEASE_TSC(cur_tsc, cfg->delay_us, tsc_per_us));
        else
            rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], clone);
        port_statistics[rx_port_id].duplicated++;
    }
}
```

`rte_pktmbuf_copy` grabs a fresh buffer from the pool and copies all bytes into it.
Now we have two independent mbufs with identical content. Both get forwarded.
Clona urmeaza acelasi path de delay ca si originalul.

### Delay — Sala de asteptare

This is the interesting one. We can't sleep because that blocks the whole thread.

Instead we have a ring buffer per PQ where packets sit until their timer expires:

```c
#define DELAY_QUEUE_SIZE  2048
#define RING_NEXT(i, sz)  (((i) + 1) % (sz))

struct delay_entry {
    struct rte_mbuf *m;
    uint64_t         release_tsc;
};
```

Timerul e TSC-ul (timestamp counter) al CPU-ului — un counter care ticaie miliarde de ori pe secunda.

```c
// cate ticks de TSC intr-un microsecund
#define TSC_PER_US(hz) ((hz) / 1000000ULL)

uint64_t tsc_per_us = TSC_PER_US(rte_get_tsc_hz());
// pe un CPU de 3.2GHz: 3200000000 / 1000000 = 3200 ticks per microsecond
```

Enqueuing a packet for delay:
```c
static inline void
delay_enqueue(struct pq_state *pqs, struct rte_mbuf *m, uint64_t release_tsc)
{
    if (pqs->dq_count >= DELAY_QUEUE_SIZE) {
        rte_pktmbuf_free(m);  // ring full, drop rather than crash
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
while (pqs->dq_count > 0) {
    if (pqs->delay_q[pqs->dq_head].release_tsc > cur_tsc)
        break;   // inca asteapta; tot ce e dupa el asteapta si el
    struct rte_mbuf *m = pqs->delay_q[pqs->dq_head].m;
    pqs->dq_head = RING_NEXT(pqs->dq_head, DELAY_QUEUE_SIZE);
    pqs->dq_count--;
    rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
}
```

`break` functioneaza pentru ca in interiorul unui PQ toate pachetele au acelasi delay
si intra in ordine, asa ca `release_tsc` creste monoton de la head la tail.
Daca head-ul nu e gata, nimic din spatele lui nu poate fi gata.

---

## Paralelism

### Two Threads, Two Ports

```
lcore 0: reads port 0  →  writes port 1
lcore 1: reads port 1  →  writes port 0
```

Each thread is pinned to its own physical CPU core by DPDK's EAL.
They run simultaneously and never wait for each other.

### No Locks — Ever

Lock-urile (mutex-urile) fac un thread sa astepte dupa altul. La milioane de pachete/secunda
chiar si cateva microsecunde de asteptare = mii de pachete pierdute. Evitam orice lock.

The trick: each thread has completely private state:

```c
struct lcore_state {
    struct pq_state pqs[NUM_PQ];
} __rte_cache_aligned;

struct lcore_state lcore_states[RTE_MAX_LCORE];
```

Thread 0 only reads/writes `lcore_states[0]`.
Thread 1 only reads/writes `lcore_states[1]`.
No overlap. No lock needed. No race condition possible.

TX buffer-ele nici ele nu se suprapun:
- Thread 0 → `tx_buffer[1]`
- Thread 1 → `tx_buffer[0]`

### False Sharing si Cache Alignment

CPU-urile incarca memoria in blocuri de 64 bytes numite cache lines.
Daca doua thread-uri au variabile in aceeasi cache line, orice write de la thread 0
il forteaza pe thread 1 sa reincerce toata linia de 64 bytes — se numeste false sharing si
distruge performanta in mod silentios chiar daca thread-urile nu citesc efectiv datele celuilalt.

`__rte_cache_aligned` tells the compiler to put the struct at a 64-byte boundary
so its data occupies its own cache lines, never shared with other thread's data.

### Prefetch

```c
rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
```

Before we process packet `i`, we tell the CPU to start loading packet data
from RAM into L1 cache now, in background, while CPU handles other things.
By the time we get to `i`, the data is already warm in cache — no stall waiting for RAM.

---

## Stats-urile

Every 1 second the main lcore prints rx/tx/drop/dup/delay counts.
For the dashboard, aggregam stats-urile din toate lcore-urile intr-un singur `pq_agg[]`:

```c
for (int pq = 0; pq < NUM_PQ; pq++) {
    uint64_t total = 0;
    uint32_t depth = 0;
    RTE_LCORE_FOREACH(lcore) {
        total += lcore_states[lcore].pqs[pq].pkt_count;
        depth += lcore_states[lcore].pqs[pq].dq_count;
    }
    pq_agg[pq].pkt_count = total;
    pq_agg[pq].dq_count  = depth;
}
```

HTTP thread-ul citeste `pq_agg[]` fara lock — worst case vede o valoare de acum un ciclu de stat,
ceea ce e complet ok pentru un dashboard.

---

## Flow complet end-to-end

```
input.pcap
    │  (pcap driver replays packets as if from real wire)
    ▼
Port 0 RX ring
    │  rte_eth_rx_burst() — grab up to 32 at a time
    ▼
pkts_burst[]
    │  classify_packet() — look at payload bytes
    ▼
PQ 0-9
    │  process_packet() — apply rules
    │
    ├── DROP?   → rte_pktmbuf_free()   (buffer inapoi in pool)
    │
    ├── DUP?    → rte_pktmbuf_copy()   (clona merge pe acelasi path)
    │
    └── DELAY?  → delay_q[pq]          (asteapta pana release_tsc trece)
        sau
        SEND    → rte_eth_tx_buffer()  (acumulam pana la 32 sau 100µs)
                        │
                        ▼
                  Port 1 TX ring
                        │  (pcap driver scrie in fisier)
                        ▼
                  output.pcap
```

---

## Intrebari frecvente

**De ce nu raw sockets?**
Raw sockets trec tot prin kernel. Syscall overhead + intrerupere per pachet.
La 10M pps asta e 10M syscalls/secunda. DPDK evita tot asta.

**Cat de precis e delay-ul?**
Sub-microsecunda. TSC ticaie miliarde de ori pe secunda si verificam delay queue-ul
la fiecare iteratie a main loop-ului (tot milioane de ori pe secunda).

**Ce se intampla daca delay queue se umple (2048 slots)?**
Noul pachet e dropped (`rte_pktmbuf_free`) in loc sa crape totul.
Degradare gratiosa sub load extrem.

**De ce circular buffer pentru delay queue?**
O(1) enqueue, O(1) dequeue, no allocation, no fragmentation, cache-friendly.
And because all packets in one PQ have same delay, the ring is always sorted
by release_tsc, so we can stop at first unexpired entry.
