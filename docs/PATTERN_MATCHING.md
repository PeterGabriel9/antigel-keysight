# Pattern Matching in classify_packet()

Note despre cum functioneaza clasificarea si de ce codul arata asa cum arata.

## De ce nu numerele de port?

Prima abordare a fost ceva de genul:

```c
if (dport == 80)  return 1;
if (dport == 443) return 2;
```

Nu functioneaza. Port numbers don't tell you what protocol is actually running —
oricine poate rula HTTP pe portul 9999 sau SSH pe portul 80. Ai gresit clasificarea tot timpul.

Abordarea cu pattern matching citeste bytes-ii efectivi din payload si ii compara.

## Cum ajungem la payload

A packet in memory looks like this:

```
[ Ethernet 14B ][ IP header 20B+ ][ TCP/UDP header 20B+ ][ payload ]
```

We navigate through it with pointer casts:

```c
struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
struct rte_ipv4_hdr  *ip  = (struct rte_ipv4_hdr *)(eth + 1);

// IHL e in 32-bit words (lower 4 bits din version_ihl), inmultim cu 4 sa avem bytes
uint32_t ip_hdr_len = (ip->version_ihl & 0x0f) << 2;
uint8_t *l4 = (uint8_t *)ip + ip_hdr_len;

// TCP data offset e in upper 4 bits din data_off, tot in 32-bit words
uint32_t tcp_hdr_len = (tcp->data_off >> 4) << 2;
uint8_t *payload = l4 + tcp_hdr_len;
```

Macro-urile din main.c wrapeaza asta:

```c
#define IP_HDR_LEN(ip)    (((ip)->version_ihl & 0x0f) << 2)
#define TCP_HDR_LEN(tcp)  (((tcp)->data_off >> 4) << 2)
#define TCP_PAYLOAD(l4)   ((uint8_t *)(l4) + TCP_HDR_LEN((struct rte_tcp_hdr *)(l4)))
#define UDP_PAYLOAD(l4)   ((uint8_t *)(l4) + sizeof(struct rte_udp_hdr))
```

## Macro-ul de baza

```c
#define PAYLOAD_STARTS_WITH(buf, buflen, pat, n) \
    ((buflen) >= (n) && memcmp((buf), (pat), (n)) == 0)
```

Bounds check first asa ca nu citim niciodata in afara buffer-ului,
apoi comparam N bytes cu memcmp.
For short patterns the compiler turns this into direct integer comparisons, very fast.

## HTTP

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

HTTP requests always start with a method verb. Responses always start with `HTTP/`.
`||` short-circuits — once one match is found we stop checking the rest.

## TLS

```c
#define IS_TLS(buf, len) (          \
    (len) >= 3                   && \
    (buf)[0] >= 0x14             && \
    (buf)[0] <= 0x17             && \
    (buf)[1] == 0x03             && \
    (buf)[2] <= 0x04 )
```

TLS starts always with a 5-byte record header. Byte 0 is content type (0x14 to 0x17),
byte 1 is major version (intotdeauna 0x03 pentru SSL3 pana la TLS 1.3),
byte 2 is minor version (0x00 to 0x04 depending on TLS version).

This fingerprint is really reliable — almost nothing else produces these exact bytes.

## SSH

```c
#define IS_SSH(buf, len) \
    PAYLOAD_STARTS_WITH(buf, len, "SSH-", 4)
```

SSH RFC mandates that both client and server must open with a version string starting with `SSH-`.
Simple 4-byte check, nu se poate confunda cu altceva.

## DNS

```c
#define DNS_OPCODE(buf)  (((buf)[2] >> 3) & 0x0f)
#define IS_DNS(buf, len) ((len) >= 12 && DNS_OPCODE(buf) == 0)
```

DNS has a 12-byte header. The opcode is in bits 14-11 of flags word (byte 2 of header).
`>> 3` moves those bits down, `& 0x0f` keeps only 4 bits.
Opcode 0 = standard query/response, care e practic tot traficul DNS real.

## NTP

```c
#define IS_NTP(buf, len) (                         \
    (len) >= 48                                 && \
    NTP_VERSION((buf)[0]) >= 3                  && \
    NTP_VERSION((buf)[0]) <= 4                  && \
    NTP_MODE((buf)[0])    >= 1                  && \
    NTP_MODE((buf)[0])    <= 5 )
```

NTP packets are minimum 48 bytes. First byte packs three fields:
bits 7-6 = leap indicator, bits 5-3 = version, bits 2-0 = mode.

```c
#define NTP_VERSION(b)  (((b) >> 3) & 0x07)  // extrage bits 5-3
#define NTP_MODE(b)     ((b) & 0x07)          // extrage bits 2-0
```

We check: at least 48 bytes, version 3 or 4, mode 1 to 5.

## IP prefix matching

```c
#define IP_IN_SLASH24(ip, net24) (((ip) >> 8) == ((net24) >> 8))
```

IPv4 is a 32-bit integer. For a /24 match we need the top 24 bits to be equal,
asa ca eliminam ultimul octet prin shift dreapta cu 8 si comparam ce ramane:

```
10.0.0.5   = 0x0A000005  >> 8 = 0x0A0000
10.0.0.99  = 0x0A000063  >> 8 = 0x0A0000  <- acelasi /24
10.0.1.5   = 0x0A000105  >> 8 = 0x0A0001  <- alt /24, nu se potriveste
```

## De ce macro-uri si nu functii normale?

No function call overhead — macro-ul se expandeaza inline la compile time.
La milioane de pachete/secunda, cativa instructiuni salvate per packet conteaza.

Dezavantajul e ca nu ai type checking si argumentele se evalueaza de mai multe ori
(problematic daca au side effects). Here we always pass simple variables so is no problem.

## Flow-ul classify_packet()

```
pachet vine
    |
    v
suficienti bytes pentru ethernet + IP? → nu → PQ 9
    |
    v
e IPv4? → nu → PQ 9
    |
    v
e ICMP?  → da → PQ 0
    |
    v
src IP in 10.0.0.0/24?    → da → PQ 6
src IP in 192.168.0.0/24? → da → PQ 7
    |
    v
TCP?
    ├── IS_HTTP(payload)?  → PQ 1
    ├── IS_TLS(payload)?   → PQ 2
    ├── IS_SSH(payload)?   → PQ 3
    └── IS_SMALL_PKT(ip)?  → PQ 8, altfel → PQ 9

UDP?
    ├── IS_DNS(payload)?   → PQ 4
    ├── IS_NTP(payload)?   → PQ 5
    └── IS_SMALL_PKT(ip)?  → PQ 8, altfel → PQ 9

alt protocol?
    └── IS_SMALL_PKT(ip)?  → PQ 8, altfel → PQ 9
```
