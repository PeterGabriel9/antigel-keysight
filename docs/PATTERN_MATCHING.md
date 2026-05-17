# Pattern Matching in classify_packet()

Quick notes on how the classification actually works and why the code looks the way it does.

## Why not just use port numbers?

The first approach was something like:

```c
if (dport == 80)  return 1;
if (dport == 443) return 2;
```

This doesn't work. Port numbers don't tell you what protocol is actually running -
anyone can run HTTP on port 9999 or SSH on port 80. The pattern matching approach
reads the actual bytes at the start of the payload and checks those instead.

## Getting to the payload

A packet in memory looks like this:

```
[ Ethernet 14B ][ IP header 20B+ ][ TCP/UDP header 20B+ ][ payload ]
```

We navigate through it with pointer casts:

```c
struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
struct rte_ipv4_hdr *ip   = (struct rte_ipv4_hdr *)(eth + 1);

// IP header length is in the lower 4 bits of version_ihl, in 32-bit words
uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) << 2;
uint8_t *l4 = (uint8_t *)ip + ip_hdr_len;

// TCP data offset is in the upper 4 bits of data_off, also in 32-bit words
uint32_t tcp_hdr_len = (tcp->data_off >> 4) << 2;
uint8_t *payload = l4 + tcp_hdr_len;
```

The macros in main.c just wrap this:

```c
#define IP_HDR_LEN(ip)   (((ip)->version_ihl & 0x0f) << 2)
#define TCP_HDR_LEN(tcp) (((tcp)->data_off >> 4) << 2)
#define TCP_PAYLOAD(l4)  ((uint8_t *)(l4) + TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)))
#define UDP_PAYLOAD(l4)  ((uint8_t *)(l4) + sizeof(struct rte_udp_hdr))
```

## The base macro

```c
#define PAYLOAD_STARTS_WITH(buf, buflen, pat, n) \
    ((buflen) >= (n) && memcmp((buf), (pat), (n)) == 0)
```

Bounds check first so we don't read past the buffer, then compare N bytes with memcmp.
For short patterns the compiler turns this into integer comparisons with no actual function call.

## HTTP

```c
#define IS_HTTP(buf, len) (
    PAYLOAD_STARTS_WITH(buf, len, "GET ",     4) ||
    PAYLOAD_STARTS_WITH(buf, len, "POST ",    5) ||
    PAYLOAD_STARTS_WITH(buf, len, "HTTP/",    5) ||
    ...
```

HTTP requests always start with a method verb. Responses always start with `HTTP/`.
The `||` short-circuits so once one matches we stop checking.

## TLS

```c
#define IS_TLS(buf, len) (
    (len) >= 3 &&
    (buf)[0] >= 0x14 && (buf)[0] <= 0x17 &&
    (buf)[1] == 0x03 &&
    (buf)[2] <= 0x04 )
```

TLS always starts with a 5-byte record header. Byte 0 is content type (0x14-0x17),
byte 1 is major version (always 0x03 for SSL3 through TLS 1.3), byte 2 is minor version.
This fingerprint is solid - very little else produces these exact bytes.

## SSH

```c
#define IS_SSH(buf, len) \
    PAYLOAD_STARTS_WITH(buf, len, "SSH-", 4)
```

The SSH RFC mandates that both client and server open the connection with a version
string starting with `SSH-`. Simple 4-byte check.

## DNS

```c
#define DNS_OPCODE(buf) (((buf)[2] >> 3) & 0x0f)
#define IS_DNS(buf, len) ((len) >= 12 && DNS_OPCODE(buf) == 0)
```

DNS has a 12-byte header. The opcode is in bits 14-11 of the flags word (byte 2 of the header).
`>> 3` moves those bits down, `& 0x0f` keeps only 4 bits. Opcode 0 is a standard query/response
which covers basically all real DNS traffic.

## NTP

```c
#define IS_NTP(buf, len) (
    (len) >= 48 &&
    NTP_VERSION((buf)[0]) >= 3 &&
    NTP_VERSION((buf)[0]) <= 4 &&
    NTP_MODE((buf)[0]) >= 1 &&
    NTP_MODE((buf)[0]) <= 5 )
```

NTP packets are at least 48 bytes. The first byte packs three fields together:
bits 7-6 = leap indicator, bits 5-3 = version, bits 2-0 = mode.
We extract version with `(b >> 3) & 0x07` and mode with `b & 0x07`.

## IP prefix matching

```c
#define IP_IN_SLASH24(ip, net24) (((ip) >> 8) == ((net24) >> 8))
```

IPv4 is a 32-bit integer. For a /24 match we just need the top 24 bits to be equal,
so shift both right by 8 (drop the last octet) and compare. For example:

```
10.0.0.5  = 0x0A000005  >>8 = 0x0A0000
10.0.0.99 = 0x0A000063  >>8 = 0x0A0000  <- same /24
10.0.1.5  = 0x0A000105  >>8 = 0x0A0001  <- different
```

## Why macros instead of functions?

No function call overhead - the macro expands inline. At millions of packets/second
even a handful of saved instructions per packet matters. The downside is no type checking
and arguments get evaluated multiple times (bad if they have side effects), but here
we always pass simple variables so it's fine.
