# TCP-Packet-Analyzer
A TCP Packet Analyzer that reads a pcap file (similar to [Wireshark](https://www.wireshark.org/)) and returns the certain answers for each TCP flow. For each flow, information about the source/destination port and addresss, the first 2 transactions sent by the sender to receiver, the sender throughput, the first 3 congestion window sizes, and the number of retransmission due to triple duplicate ack and timeout.

# Examples
```bash
$ python analysis_pcap_tcp.py 
There are a total of 3 TCP flows

Flow 1 Information:
PART A
a) (43498, '130.245.145.12', 80, '128.208.2.198')
b) The first 2 transactions:
Tranaction 1: 
        Sequence number: 705,669,103
        Ack number: 1,921,750,144
        Receive Window Size: 49,152
Tranaction 2: 
        Sequence number: 705,669,127
        Ack number: 1,921,750,144
        Receive Window Size: 49,152
c) Throughput: 5,327,141.878039 bytes/second (10,320,080 bytes sent in 1.9373 seconds)
PART B
1) The first 3 congestion window sizes: [10, 20, 33]
2)      Retransmission due to triple duplicate ack: 2
        Retransmission due to timeout: 1
====================================================================================================
Flow 2 Information:
PART A
a) (43500, '130.245.145.12', 80, '128.208.2.198')
b) The first 2 transactions:
Tranaction 1: 
        Sequence number: 3,636,173,852
        Ack number: 2,335,809,728
        Receive Window Size: 49,152
Tranaction 2: 
        Sequence number: 3,636,173,876
        Ack number: 2,335,809,728
        Receive Window Size: 49,152
c) Throughput: 1,267,619.603100 bytes/second (10,454,760 bytes sent in 8.2476 seconds)
PART B
1) The first 3 congestion window sizes: [10, 20, 33]
2)      Retransmission due to triple duplicate ack: 4
        Retransmission due to timeout: 90
====================================================================================================
Flow 3 Information:
PART A
a) (43502, '130.245.145.12', 80, '128.208.2.198')
b) The first 2 transactions:
Tranaction 1: 
        Sequence number: 2,558,634,630
        Ack number: 3,429,921,723
        Receive Window Size: 49,152
Tranaction 2: 
        Sequence number: 2,558,634,654
        Ack number: 3,429,921,723
        Receive Window Size: 49,152
c) Throughput: 1,607,862.811638 bytes/second (1,071,832 bytes sent in 0.6666 seconds)
PART B
1) The first 3 congestion window sizes: [10, 20, 33]
2)      Retransmission due to triple duplicate ack: 0
        Retransmission due to timeout: 0
====================================================================================================
```

# Installation
Dependencies:
- dpkt 
```bash
$ git clone https://github.com/weiwenzhou/TCP-Packet-Analyzer.git
$ cd TCP-Packet-Analyzer/
TCP-Packet-Analyzer$ pip install -r requirements.txt
```

# Usage
```bash
$ python analysis_pcap_tcp.py 
```