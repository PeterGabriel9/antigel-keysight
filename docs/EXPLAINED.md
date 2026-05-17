# Cum functioneaza emulator-ul de retea — pe intelesul tuturor
**(How the Network Emulator Works — explained simply)**

Sa ne imaginam ca suntem un postal worker intr-un oficiu postal imens.
Camioane vin si lasa pachete (network packets) la usa noastra non-stop.
Job-ul nostru: sortam pachetele, aplicam niste reguli unora intentionat,
si le trimitem mai departe pe alta usa.

Asta face exact programul asta — dar cu network packets in loc de cutii fizice.

---

## Imaginea generala

```
Packets vin din retea
        |
        v
  [ Le primim ]
        |
        v
  [ Decidem in ce "gramada" merge fiecare ]
        |
        v
  [ Aplicam regulile: drop, dup, delay ]
        |
        v
  [ Trimitem ce a supravietuit ]
```

There are **two ports** (doors). One CPU thread (lcore) handles each door.
- Thread 0 reads from port 0, sends out port 1.
- Thread 1 reads from port 1, sends out port 0.

Nu comunica intre ei. Sunt complet independenti.

---

## Ce e un "packet"?

A packet is just a small chunk of data traveling over the network.
Think of it like an envelope. The envelope has:
- **Ethernet header** — cine l-a trimis si catre cine (outside of envelope)
- **IP header** — the address (oras, strada)
- **TCP/UDP header** — numarul apartamentului
- **Data** — continutul efectiv

In C, DPDK gives us each packet as a pointer: `struct rte_mbuf *m`.
Is just a struct that holds a pointer to raw bytes of packet.

---

## Pasul 1 — Primim pachetele (`rte_eth_rx_burst`)

```c
unsigned nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
```

This is like opening the mailbox and grabbing up to 32 envelopes at once.
`nb_rx` tells us how many we actually got — can be 0 if nothing arrived yet.

Facem asta intr-o bucla infinita pana cineva apasa Ctrl+C.

---

## Pasul 2 — Cele 10 gramezi (Profile Queues)

We have 10 piles on our desk. Every incoming packet goes into exactly one pile.
We call them **Profile Queues — PQ 0 pana la PQ 9**.

The function `classify_packet(m)` decides which pile. It returns a number from 0 to 9.

Cum decide? Se uita direct in continutul packetului, nu in numarul de port.
(Numerele de port sunt inutile — poti rula orice protocol pe orice port.)
Instead we look at the actual bytes in the payload and check for known signatures:

```
ICMP?                              → PQ 0  (ping si altele d-astea)
Payload incepe cu GET/POST/HTTP/?  → PQ 1  (HTTP)
Payload incepe cu 0x16 0x03 ...?   → PQ 2  (TLS/HTTPS)
Payload incepe cu "SSH-"?          → PQ 3  (SSH)
UDP + DNS header (opcode=0)?       → PQ 4  (DNS queries)
UDP + NTP header (48 bytes, VN=3/4)? → PQ 5 (NTP)
IP sursa din 10.0.0.0/24?          → PQ 6
IP sursa din 192.168.0.0/24?       → PQ 7
Pachet mic (sub 128 bytes IP total)? → PQ 8
Orice altceva                      → PQ 9  (default)
```

---

## Pasul 3 — Regulile pentru fiecare gramada

Each pile has 3 configurable rules:

| Regula | Ce face |
|--------|---------|
| `drop_n` | Arunca N pachete din fiecare 10 |
| `dup_n` | Dubleaza N pachete din fiecare 10 (trimite si copie) |
| `delay_us` | Tine pachetele N microsecunde inainte sa le trimiti |

### Drop

```c
uint64_t count = pqs->pkt_count++;

if (SHOULD_DROP(count, cfg->drop_n)) {
    rte_pktmbuf_free(m);  // inapoi in pool
    port_statistics[rx_port_id].dropped++;
    return;
}
```

`count % 10` cicleaza: 0,1,2,...,9,0,1,2,... si asa mai departe.
Daca `drop_n = 2` atunci drop-am cand count%10 e 0 sau 1 → exact 2 din 10.

Important: numaram across bursts, nu per burst.
If we count only inside burst and burst have only 7 packets, positions 7-9 are never seen.
Cu `pkt_count` persistent nu avem problema asta — vede FIECARE pachet.

### Duplicate

```c
if (SHOULD_DUP(count, cfg->dup_n)) {
    struct rte_mbuf *clone = rte_pktmbuf_copy(m, netem_pktmbuf_pool, 0, UINT32_MAX);
    if (clone != NULL) {
        // trimitem clona pe acelasi path ca originalul
    }
}
// trimitem si originalul oricum
```

`rte_pktmbuf_copy` face o copie completa si independenta a pachetului.
E ca o xerox a plicului. Ambele copii merg mai departe.

### Delay — Sala de asteptare

Asta e partea cea mai interesanta. Nu putem folosi `sleep()` pentru ca ar bloca
intregul thread si n-am mai putea procesa alte pachete.

In schimb avem un ring buffer per PQ unde pachetele stau pana le vine randul:

```c
struct delay_entry {
    struct rte_mbuf *m;
    uint64_t release_tsc;  // cand are voie sa iasa
};
```

The timer we use is the CPU's TSC register — a counter that ticks billions of times per second.
`rte_rdtsc()` reads it in single instruction, no syscall needed.

```c
// cate ticks de TSC intr-un microsecund
uint64_t tsc_per_us = rte_get_tsc_hz() / 1000000;
// pe un CPU de 3.2GHz: 3200000000 / 1000000 = 3200 ticks/us
```

Every main loop iteration we check if anyone in waiting room can leave:

```c
while (pqs->dq_count > 0) {
    if (pqs->delay_q[pqs->dq_head].release_tsc > cur_tsc)
        break;  // inca asteapta
    struct rte_mbuf *m = pqs->delay_q[pqs->dq_head].m;
    pqs->dq_head = RING_NEXT(pqs->dq_head, DELAY_QUEUE_SIZE);
    pqs->dq_count--;
    rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
}
```

The `break` works because packets in same PQ have same delay and arrive in time order,
so release_tsc values are always increasing from head to tail.
Daca head-ul nu e gata, nimeni de dupa el nu poate fi gata.

---

## Pasul 4 — Trimiterea pachetelor

Sending one packet at a time is very inefficient. DPDK uses a TX buffer — a small staging area:

```c
rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], m);
```

When the buffer fills up (32 packets), DPDK sends them all at once automatically.
Every 100 microseconds we force flush whatever still remains in buffer:

```c
rte_eth_tx_buffer_flush(tx_port_id, 0, tx_buffer[tx_port_id]);
```

---

## Paralelism fara lock-uri

Cel mai important design decision din proiect.

Thread 0 are propriul `lcore_states[0]` cu 10 `pq_state` struct-uri.
Thread 1 are propriul `lcore_states[1]` cu 10 `pq_state` struct-uri.

Nu se ating niciodata pe date comune. Nu exista mutex, no atomic operations, nothing.
E safe pentru ca fiecare thread citeste si scrie DOAR propriul state.

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
```

Si TX buffer-ele sunt diferite — thread 0 scrie in `tx_buffer[1]`, thread 1 in `tx_buffer[0]`.
So even on the send side there is no conflict at all.

---

## De ce DPDK si nu ceva normal?

Normal, cand un pachet vine la placa de retea se intampla urmatoarele:

```
NIC receives packet
    → NIC interrupts the CPU ("hey I have data!")
    → kernel wakes up
    → kernel copies packet from NIC memory to kernel memory
    → kernel copies from kernel memory to your program's memory
    → your program finally sees it
```

Doua copieri si o intrerupere per packet. La 10 milioane de pachete pe secunda
asta inseamna 10 milioane de syscalls/secunda. CPU-ul nu mai are timp de nimic altceva.

DPDK bypasses all of that:

```
NIC receives packet
    → NIC writes directly into memory your program owns (DMA)
    → your program reads it directly
```

No interrupt. No copy. No kernel. Just your code talking directly to hardware.
Trade-off: DPDK "fura" un CPU core care ruleaza intr-o bucla infinita
verificand constant daca a mai venit ceva — se numeste **poll mode**.
Consuma curent mai mult dar latenta e minima si throughput-ul e maxim.

---

## Glosar rapid

| Termen | Ce inseamna |
|--------|-------------|
| `mbuf` | Un struct care tine un singur pachet |
| `mempool` | Rezerva pre-alocata de mbuf-uri, nu mai facem malloc in timpul procesarii |
| `lcore` | Un CPU thread fixat pe un core fizic |
| `TSC` | Timer-ul intern al CPU-ului, citit cu o singura instructiune assembly |
| `tx_buffer` | Zona de staging inainte de a trimite efectiv pachetele catre NIC |
| port | O interfata de retea (o usa pe care intra sau ies pachetele) |
| Profile Queue | Una din cele 10 gramezi, fiecare cu propriile reguli de drop/dup/delay |
| Circular buffer | Un array in care tail-ul se intoarce la inceput cand ajunge la final |
