#!/bin/bash

# Start the application
# - with 100MB of RAM (-m 100)
# - without HugePages, as we don't use a physical device, only pcap virtual devices
./build/netem --no-huge -l 0-1 -n 1 -m 100 --vdev 'net_pcap0,rx_pcap=/home/student/input.pcap,,infinite_rx=0' --vdev 'net_pcap1,tx_pcap=/home/student/output.pcap'
