import dpkt
from collections import OrderedDict

FILE_PATH = "assignment2.pcap"
TCP_COUNT = 0
COUNT = 0
SENDER = "130.245.145.12"
RECEIVER = "128.208.2.198"
REQUESTS = {}
TRANSACTION = {}
THROUGHPUT = {}
PACKET = {}

INITIAL_SEQ_ACK = {}
SEQ_TO_ACK = {}

def get_ip(data):
    """
    Returns the IP addresss encode as 4 bytes in as . dot separated string.
    """
    data = data.hex()
    return ".".join([str(int(data[i:i+2], base=16)) for i in range(0, len(data), 2)])

def process_pcap(file):
    global COUNT
    pcap = dpkt.pcap.Reader(f)
    # print(pcap)
    for timestamp, buf in pcap:
        COUNT += 1
        e = dpkt.ethernet.Ethernet(buf)
        # print("ethernet", len(e))
        if isinstance(e.data, dpkt.ip.IP):
            # print(e.dst, e.src, e.type)
            ip = e.data
            # print("ip", len(ip))
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                # print("tcp", len(tcp))
                src = get_ip(ip.src)
                dst = get_ip(ip.dst)
                
                iden = (tcp.sport, src, tcp.dport, dst)
                # SEQ/ACK number
                combo = sorted([tcp.sport, tcp.dport]) + sorted([src, dst])
                combo = tuple(combo)
                if len(INITIAL_SEQ_ACK.get(combo, {})) == 0:
                    INITIAL_SEQ_ACK[combo] = {'SEQ': tcp.seq}
                elif len(INITIAL_SEQ_ACK.get(combo, {})) == 1:
                    INITIAL_SEQ_ACK[combo]['ACK'] = tcp.seq                    

                SEQ_TO_ACK[tcp.seq] = tcp.seq
                if REQUESTS.get(iden, False):
                    THROUGHPUT[iden] += len(tcp)
                    PACKET[iden] += 1
                    if len(TRANSACTION[iden]) == 0 and tcp.seq-INITIAL_SEQ_ACK[combo]['SEQ'] != 1:
                        # TRANSACTION[iden]["FIRST"] = (tcp.seq, tcp.ack, tcp.win)
                        TRANSACTION[iden]["FIRST"] = (tcp.seq-INITIAL_SEQ_ACK[combo]['SEQ'], tcp.ack-INITIAL_SEQ_ACK[combo]['ACK'], tcp.win)
                    elif len(TRANSACTION[iden]) == 1:
                        # TRANSACTION[iden]["SECOND"] = (tcp.seq, tcp.ack, tcp.win)
                        TRANSACTION[iden]["SECOND"] = (tcp.seq-INITIAL_SEQ_ACK[combo]['SEQ'], tcp.ack-INITIAL_SEQ_ACK[combo]['ACK'], tcp.win)
                if not (REQUESTS.get(iden, False)) and src == SENDER:
                    REQUESTS[iden] = COUNT
                    TRANSACTION[iden] = {}
                    THROUGHPUT[iden] = len(tcp)
                    PACKET[iden] = 1
                    # print(bin(tcp.flags))
                # if tcp.flags & 0x1 and src == SENDER:
                    # print(COUNT, iden)
                    # print(bin(tcp.flags))
                    # TCP_COUNT += 1

                # if src == SENDER:
                    # TCP_COUNT += 1

        # break
# print(dpkt.pcap.FileHdr.__hdr_len__)
# print(dpkt.pcap.PktHdr.__hdr_len__)

if __name__ == "__main__":
    with open(FILE_PATH, 'rb') as f:
        process_pcap(f)
    
    for i in INITIAL_SEQ_ACK:
        print(i, INITIAL_SEQ_ACK[i])

    print("REQUESTS")
    for i in REQUESTS:
        print(REQUESTS[i], i, f"{THROUGHPUT[i]:,d} bytes", f"{PACKET[i]} packets")
        print(TRANSACTION[i])
    print(len(REQUESTS))