# Keysight Student Challenge 2026
## Implement a Network Emulator to Duplicate, Drop, and Shape Network Traffic

> Supervisor: Cosmin Chenaru  
> Location: Politehnica University of Bucharest  
> Date: May 16–17, 2026

---

# Introduction

Modern distributed systems rarely operate in ideal conditions. In real-world networks, packets may be delayed, dropped, duplicated, or reordered due to congestion, hardware limitations, routing behavior, or unstable links.

A **network emulator** is a system designed to reproduce these imperfect conditions in a controlled environment, allowing developers and researchers to test how applications behave under realistic network scenarios.

In this challenge, you will design and implement your own network emulator capable of simulating such behaviors.

Incoming packets will be:
- classified based on configurable patterns,
- routed into multiple queues,
- processed according to queue-specific rules,
- and forwarded after traffic shaping operations are applied.

Each queue may:
- drop packets,
- duplicate packets,
- delay packets,
- or combine multiple behaviors together.

The objective is to mimic the unpredictability of real networks while maintaining precise control over packet processing.

---

# Why DPDK?

[DPDK](https://www.dpdk.org/) is a high-performance open-source framework used for fast packet processing in user space.

By bypassing the traditional Linux kernel networking stack, DPDK enables applications to process millions of packets per second with very low latency.

This makes DPDK ideal for:
- software routers,
- firewalls,
- packet analyzers,
- network emulators,
- and other high-performance networking applications.

---

# Challenge Overview

Your application must:

1. Receive incoming packets
2. Classify packets into queues
3. Apply queue-specific transformations
4. Forward processed packets

![Application overview](docs/diagrams/keysight-challenge-2026-fig1.drawio.svg)

---

# Packet Processing Pipeline

```text
RX Port
   │
   ▼
Packet Classification
   │
   ├──► Profile Queue 0
   ├──► Profile Queue 1
   ├──► ...
   └──► Profile Queue 9
              │
              ▼
      Packet Processing
      - Drop
      - Duplicate
      - Delay
              │
              ▼
           TX Port
```

---

# Core Requirements

## Packet Classification

Incoming packets must be classified based on **10 hardcoded patterns**.

Each packet must be routed into one of the 10 **Profile Queues (PQ)**.

The classification criteria are implementation-defined, but should be deterministic and efficient.

Examples:
- IP address
- UDP/TCP port
- Protocol type
- Packet payload pattern
- VLAN ID

---

# Queue Behaviors

Each Profile Queue (PQ) must support configurable behaviors.

## Packet Drop

Example:
- Drop 1 packet out of every 10 packets.

## Packet Duplication

Example:
- Duplicate 3 packets out of every 10 packets.

## Packet Delay

Example:
- Delay packets by:
  - 1 ms
  - 100 µs
  - or any configurable interval.

---

# Parallelism Requirements

The application must process packets in parallel.

## Constraints

- No global locks allowed
- The implementation must scale with the number of CPU cores
- Packet processing must remain thread-safe

## Allowed Technologies

You may use:
- POSIX Threads (`pthreads`)
- `rte_thread_create()`
- OpenMP

---

# Performance Metrics

Your implementation will be evaluated based on:

## Functional Correctness

- Correct packet classification
- Correct packet dropping behavior
- Correct packet duplication behavior
- Correct delay implementation

## Performance

- Throughput (packets per second)
- Latency
- CPU scalability
- Delay precision

Target delay precision:
- Microseconds preferred
- Milliseconds acceptable

---

# Bonus Challenges

Additional points may be awarded for:

- Efficient handling of bursty traffic
- Queue overflow protection
- Lock-free designs
- NUMA-aware optimizations
- Advanced scheduling strategies
- Runtime queue configuration
- Statistics and monitoring

---

# Development Environment

## Windows

Install:
- Docker Desktop
- Git for Windows

## Linux

Install:
- Docker
- Git

---

# Repository Setup

Fork this repository and clone the new fork

```bash
git clone git@github.com:$YOUR_USER/keysight-challenge-2026.git
```

## Repository Structure

```
setup/
 ├── start_container.sh
 ├── stop_container.sh
 ├── input.pcap
 └── Dockerfile
netem/
 ├── main.c
 ├── run.sh
 └── meson.build
```

The `start_container.sh` script will build the Docker container using the commands in the Dockerfile.

The `input.pcap` is a packet capture file (can be opened by Wireshark) and will be used for testing your application. Contains 1000 packets with various frame sizes.

`main.c` is the application source file. It is a DPDK application built outside of the DPDK source tree. Can be executed with the `run.sh` script.

---

# Starting the Development Container

Inside the `setup/` folder:

```bash
./start_container.sh
```

---

# Accessing the Container

Once the build completes, you can access the container in two ways.

## Option 1 — Browser Terminal

Open:

```text
http://localhost:8000
```
Login credentials: student/keysight2026

## Option 2 — Docker Shell

```bash
docker ps
docker exec -it <CONTAINER_ID> /bin/bash
```

---

# Expected Deliverables

Each team must submit:

- Source code
- Build instructions
- Short architecture description
- Performance measurements
- Known limitations (if any)

---

# What You Will Learn

This challenge introduces concepts used in real high-performance networking systems:

- Packet processing
- Traffic shaping
- Parallel programming
- Lock-free synchronization
- Queue design
- Low-latency systems
- DPDK programming
- Performance optimization

---

# Minimal application structure

The netem/main.c is based on the L2fwd (Layer 2 forwarder) example in DPDK. It reads the packets from a "port" (a network interface) and sends them back on another port. To make development easier, we will be using two virtual devices from DPDK, implemented by the PCAP ethdev. Usually DPDK is started with two or more physical devices, but this would make this challenge more difficult to implement.

DPDK usually reads the packets from a network device using the [rte_eth_rx_burst()](https://doc.dpdk.org/api/rte__ethdev_8h.html#a3e7d76a451b46348686ea97d6367f102) call. Reading packets in a burst (typically 32 packets) is more efficient than reading a single packet at a time. In the `netem` application, the packets are stored inside an array of packets (the `pkts_burst` variable) in netem_main_loop(). After processing, the packets will be send to the network device with a call to [rte_eth_tx_buffer()](https://doc.dpdk.org/api/rte__ethdev_8h.html#a0e941a74ae1b1b886764bc282458d946).

Two threads will be created by the netem application, one for each port, with a call to rte_eal_mp_remote_launch().

---

# Validation

Your solution may be tested with:
- bursty traffic
- malformed packets
- large delays
- high packet rates

To validate your solution, push the code changes to your repository and create a Merge Request.

---

# Additional Resources

- DPDK Documentation  
  https://doc.dpdk.org/guides/

- DPDK API Reference  
  https://doc.dpdk.org/api/

- OpenMP Documentation  
  https://www.openmp.org/resources/

---

# Good Luck!

Focus on:
- correctness,
- scalability,
- simplicity,
- and performance.

Small, clean, efficient designs usually outperform overly complex systems.
