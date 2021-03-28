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

# Explanation
### Part A
The first 2 transactions are found by separating the three-way handshake from the rest of the TCP flow. This is done by checking syn packet sent by sender and a corresponding syn, ack packet from the receiver which has an ack that is one greater than the sender's syn packet's sequence number. Using this ack from the receiver, we look for the an ack packet from sender in response that has an ack number 1 more than the sequence number of the receiver's ack. In doing this, we found the packets for the three way handshake of flow. In addition, we need to check the payload on the last ack in the handshake. If the payload is not zero, then it is piggy-backed packet and is treated as the first transaction. 

The sender throughput is found using the amount of bytes sent by the sender from the first transaction (the first ack sent by the sender after the handshake) and the time it receives the last ack packet from the receiver. The last ack packet is found by getting the fin,ack packet sent by receiver. Then I exclude all the packets sent by sender after the fin,ack packet. The period is found using the difference between the timestamp of the fin, ack packet and the first transaction.

### Part B
The first three congestion window sizes are found by first estimating the time for one RTT. This is done by searching for the time it takes to finish the first transaction, which is difference between the timestamp of the first ack sent by the sender and timestamp of the first ack sent by the receiver. The original difference is rounded to the hundredth place. Then, I found the number of packets sent by the sender between each RTT. The congestion windows are double every RTT.

The total retransmission packets are found by checking number of duplicate sequence numbers in the ack packets sent by the sender. The number of times a retransmission occurs due to triple duplicate ack is by finding number of packets sent by the receiver with the same ack number that appears more than 3 times (minimum packets for a triple duplicate ack is 3 duplicate acks and actual ack in response) subtracting the number of packets that have triple duplicate acks due to a packet being out of order. This is found by first getting the ack that appear more than 3 times and finding the intersection of those ack with the seq of the packets sent by the sender with duplicate sequence numbers. To differentiate the packets retransmitted due to a triple duplicate ack and out of order packets, I check if the first duplicate ack in receiver appears before or after the retransmitted packet. For out of order packets, the first duplicate ack appears after the retransmitted packet. The number of retransimission is the difference between the total retransmission packets and the number of retransmission due to triple duplicate ack.