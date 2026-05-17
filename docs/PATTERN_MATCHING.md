# How the Pattern Matching Classification Works

This explains what we changed in `classify_packet()` and why,
so you can understand the actual C techniques used.

---

## The Old Way (port-based, bad)

```c
if (dport == 80)  return 1;  // "this is HTTP"
if (dport == 443) return 2;  // "this is HTTPS"
```

This just reads the destination port number from the TCP header.
The problem: port numbers mean nothing. Anyone can run HTTP on port 9999
or SSH on port 80. You'd misclassify the packet every time.

---

## The New Way (payload pattern matching)

We actually open the packet and look at the bytes inside.
Every protocol has a recognizable byte signature at the start of its payload.

---

## How We Get to the Payload

A packet looks like this in memory:

```
[  Ethernet header  ][  IP header  ][  TCP header  ][  actual data  ]
      14 bytes          20+ bytes       20+ bytes       you're here
```

We get each layer by casting a pointer:

```c
// step 1: ethernet header is at byte 0 of the packet
struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

// step 2: IP header is right after ethernet
// eth+1 moves the pointer forward by sizeof(struct rte_ether_hdr) bytes
struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);

// step 3: TCP/UDP header is after IP
// IP header length is in the lower 4 bits of version_ihl, multiplied by 4
uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) << 2;
uint8_t *l4 = (uint8_t *)ip + ip_hdr_len;

// step 4: payload is after the TCP header
// TCP data offset is in the upper 4 bits of data_off, multiplied by 4
uint32_t tcp_hdr_len = (tcp->data_off >> 4) << 2;
uint8_t *payload = l4 + tcp_hdr_len;
```

We wrapped all of this in macros so the classify function stays readable:

```c
#define IP_HDR_LEN(ip)   (((ip)->version_ihl & 0x0f) << 2)
#define TCP_HDR_LEN(tcp) (((tcp)->data_off >> 4) << 2)
#define TCP_PAYLOAD(l4)  ((uint8_t *)(l4) + TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)))
#define UDP_PAYLOAD(l4)  ((uint8_t *)(l4) + sizeof(struct rte_udp_hdr))
```

---

## The Generic Pattern Macro

The base building block for all our protocol detection:

```c
#define PAYLOAD_STARTS_WITH(buf, buflen, pat, n) \
    ((buflen) >= (n) && memcmp((buf), (pat), (n)) == 0)
```

Two things happen here:
1. `(buflen) >= (n)` — bounds check first so we never read past the end of the buffer
2. `memcmp((buf), (pat), (n))` — compare the first `n` bytes against the pattern

`memcmp` returns 0 if the bytes match, non-zero otherwise.
For short fixed-length patterns the compiler turns this into integer comparisons — very fast.

---

## HTTP Detection

```c
#define IS_HTTP(buf, len) (                             \
    PAYLOAD_STARTS_WITH(buf, len, "GET ",     4) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "POST ",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "HTTP/",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "HEAD ",    5) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "PUT ",     4) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "DELETE ",  7) ||    \
    PAYLOAD_STARTS_WITH(buf, len, "OPTIONS ", 8) )
```

HTTP requests always start with a method verb (`GET`, `POST`, etc.).
HTTP responses always start with `HTTP/1.1 200 OK` or similar.

So we check the first few bytes of the TCP payload against each of these strings.
The `||` means "any one match is enough". Short-circuit evaluation means as soon
as one matches, we stop checking the rest.

---

## TLS Detection

```c
#define IS_TLS(buf, len) (                      \
    (len) >= 3                               && \
    (buf)[0] >= 0x14 && (buf)[0] <= 0x17    && \
    (buf)[1] == 0x03                         && \
    (buf)[2] <= 0x04 )
```

TLS (used by HTTPS, SMTPS, etc.) always starts with a 5-byte record header:
- Byte 0: **content type** — always one of:
  - `0x14` = ChangeCipherSpec
  - `0x15` = Alert
  - `0x16` = Handshake
  - `0x17` = ApplicationData
- Byte 1: **major version** — always `0x03` (used by SSL3, TLS 1.0, 1.1, 1.2, 1.3)
- Byte 2: **minor version** — `0x00` to `0x04` depending on exact TLS version

We check all three bytes with `&&` meaning all must match.
This is a very reliable fingerprint — almost nothing else produces these bytes.

---

## SSH Detection

```c
#define IS_SSH(buf, len) \
    PAYLOAD_STARTS_WITH(buf, len, "SSH-", 4)
```

The SSH protocol says that the very first thing both client and server must send
is a version string starting with `SSH-`. This is in the SSH RFC itself.

So this is a single 4-byte string comparison — dead simple, always correct.

---

## DNS Detection

```c
#define DNS_OPCODE(buf)  (((buf)[2] >> 3) & 0x0f)
#define IS_DNS(buf, len) \
    ((len) >= 12 && DNS_OPCODE(buf) == 0)
```

DNS messages have a fixed 12-byte header. The 3rd byte (index 2) contains flags:
```
bit 7    : QR (0=query, 1=response)
bits 6-3 : OPCODE (0=standard, 1=inverse, 2=status)
bits 2-0 : AA, TC, RD flags
```

We extract the OPCODE with: `(buf[2] >> 3) & 0x0f`
- `>> 3` shifts the bits right by 3, moving bits 6-3 into positions 3-0
- `& 0x0f` masks to keep only the lower 4 bits

OPCODE == 0 means it's a standard DNS query or response, which covers basically all real DNS traffic.

---

## NTP Detection

```c
#define NTP_VERSION(b)   (((b) >> 3) & 0x07)
#define NTP_MODE(b)      ((b) & 0x07)

#define IS_NTP(buf, len) (                          \
    (len) >= 48                                  && \
    NTP_VERSION((buf)[0]) >= 3                   && \
    NTP_VERSION((buf)[0]) <= 4                   && \
    NTP_MODE((buf)[0])    >= 1                   && \
    NTP_MODE((buf)[0])    <= 5 )
```

NTP packets are exactly 48 bytes minimum. The first byte packs three fields:
```
bits 7-6 : LI   (leap indicator, 0-3, we don't check this)
bits 5-3 : VN   (version number, we want 3 or 4)
bits 2-0 : Mode (1=sym_active, 2=sym_passive, 3=client, 4=server, 5=broadcast)
```

Extracting version: `(byte >> 3) & 0x07`
- `>> 3` moves bits 5-3 into positions 2-0
- `& 0x07` masks to 3 bits

Extracting mode: `byte & 0x07`
- `& 0x07` keeps only the lower 3 bits

We check: packet is at least 48 bytes, version is 3 or 4, mode is 1-5.
All three conditions must hold (`&&`).

---

## IP Prefix Matching

```c
#define IP_IN_SLASH24(ip, net24)   (((ip) >> 8) == ((net24) >> 8))
```

An IPv4 address is a 32-bit integer. For example, 10.0.0.5 is `0x0A000005`.

To check if it's in the 10.0.0.0/24 network (first 24 bits must match),
we throw away the last 8 bits with `>> 8` and compare:
```
0x0A000005 >> 8 = 0x0A0000
0x0A000000 >> 8 = 0x0A0000   ← same!

0x0A000105 >> 8 = 0x0A0001   ← different, this is 10.0.1.5, not in our /24
```

---

## Small Packet Detection

```c
#define IS_SMALL_PKT(ip) \
    (rte_be_to_cpu_16((ip)->total_length) < SMALL_PKT_BYTES)
```

`ip->total_length` is the total IP packet size in bytes (stored big-endian in the header).
`rte_be_to_cpu_16` swaps the bytes to host order so we can compare it normally.
If it's less than 128 bytes, it goes into PQ 8 (assuming it didn't match anything above).

---

## Why Macros Instead of Functions?

Two reasons:

1. **No function call overhead** — macros expand inline at compile time.
   At millions of packets/second, saving even a handful of CPU instructions per
   packet adds up.

2. **Readable code** — `IS_TLS(payload, len)` is much clearer than
   `len >= 3 && buf[0] >= 0x14 && buf[0] <= 0x17 && buf[1] == 0x03 && buf[2] <= 0x04`
   inline in the middle of the classify function.

The downside of macros is they have no type checking and can evaluate arguments
multiple times (bad if the argument has side effects like `IS_TLS(get_payload(), len)`
would call `get_payload()` once per condition). Here we always pass simple variables
so that's not an issue.

---

## The Classify Function Flow

```
packet arrives
    |
    v
enough bytes for ethernet + IP? → no → PQ 9
    |
    v
is IPv4? → no → PQ 9
    |
    v
is ICMP?  → yes → PQ 0
    |
    v
src IP in 10.0.0.0/24?    → yes → PQ 6
src IP in 192.168.0.0/24? → yes → PQ 7
    |
    v
TCP?
    ├── IS_HTTP(payload)?  → PQ 1
    ├── IS_TLS(payload)?   → PQ 2
    ├── IS_SSH(payload)?   → PQ 3
    └── IS_SMALL_PKT(ip)?  → PQ 8
                             else → PQ 9

UDP?
    ├── IS_DNS(payload)?   → PQ 4
    ├── IS_NTP(payload)?   → PQ 5
    └── IS_SMALL_PKT(ip)?  → PQ 8
                             else → PQ 9

other protocol?
    └── IS_SMALL_PKT(ip)?  → PQ 8
                             else → PQ 9
```

---

## Key C Concepts Used

| Concept | Where | What it does |
|---------|-------|-------------|
| Pointer casting | `(struct rte_ipv4_hdr *)(eth + 1)` | Reinterpret the bytes at a known offset as a specific struct |
| Pointer arithmetic | `eth + 1` | Moves pointer forward by `sizeof(*eth)` bytes |
| Bit masking | `& 0x0f`, `& 0x07` | Keep only specific bits |
| Bit shifting | `>> 3`, `>> 4` | Move bits to lower positions for comparison |
| `memcmp` | `PAYLOAD_STARTS_WITH` | Compare N bytes of memory — faster than a loop |
| Short-circuit eval | `&&` and `\|\|` | Stop evaluating as soon as the result is known |
| Macro with args | `#define IS_TLS(buf, len)` | Inline code expansion with parameters |
