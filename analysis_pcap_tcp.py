import datetime
import dpkt
from collections import Counter

FILE_PATH = "p01.pcap"
SENDER = "10.179.59.38"
RECEIVER = "10.68.33.170"


class Packet():
    def __init__(self, data):
        self.ethernet = dpkt.ethernet.Ethernet(data)
        self.ip = self.ethernet.data
        self.tcp = self.ip.data

    def get_id(self):
        return (self.tcp.sport, get_ip(self.ip.src), self.tcp.dport, get_ip(self.ip.dst))

    def get_tcp_size(self):
        return len(self.tcp)

    def get_payload_size(self):
        return len(self.tcp.data)

    def get_tcp_flags(self):
        return self.tcp.flags

    def get_seq(self):
        return self.tcp.seq

    def get_ack(self):
        return self.tcp.ack

    def get_window_size(self):
        return self.tcp.win

    def get_src(self):
        return get_ip(self.ip.src)


class Flow():
    def __init__(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver

        # combine packets
        self.flow = sorted(self.sender + self.receiver, key=lambda x: x[0])
        # find handshake
        self.__separate_handshake()
        # get window size scaling factor
        options = dpkt.tcp.parse_opts(self.handshake[0][-1].tcp.opts)
        window_scale = [value for opt, value in options if opt == dpkt.tcp.TCP_OPT_WSCALE][0]
        self.win_scaling = 2 ** int(window_scale.hex(), base=16)
        print("window_scale: " + str(self.win_scaling))

    def __separate_handshake(self):
        # get the syn packet from sender
        sender_syn = None
        for packet in self.sender:
            if packet[-1].get_tcp_flags() & 0x2:
                sender_syn = packet
                break
        if sender_syn == None:
            print("No sender_syn")
        print("sender_syn's seq: " + str(sender_syn[-1].get_seq()))

        # get the syn, ack packet from receiver who's ack is 1 more than seq of the sender's syn packet
        receiver_syn = None
        for packet in self.receiver:
            if packet[-1].get_tcp_flags() & 0x12 and packet[-1].get_ack() == sender_syn[-1].get_seq() + 1:
                receiver_syn = packet
                break
        if receiver_syn == None:
            print("No receiver_syn")
        print("receiver_syn's seq: " + str(receiver_syn[-1].get_seq()))

        # get the ack packet from sender who's ack is 1 more than seq of syn,ack packet
        sender_ack = None
        for packet in self.sender:
            if packet[-1].get_tcp_flags() == 0x10:
                if packet[-1].get_ack() == receiver_syn[-1].get_seq() + 1:
                    sender_ack = packet
                    break
        if sender_ack == None:
            print("No sender_ack")
        print("send_ack's seq: " + str(sender_ack[-1].get_seq()))

        # get index in flow
        index_to_split = self.flow.index(sender_ack)
        self.handshake = self.flow[:index_to_split + 1]
        # check if the sender_ack is piggyback
        if sender_ack[-1].get_payload_size() != 0:  # sender_ack is piggyback
            index_to_split -= 1
        self.flow = self.flow[index_to_split + 1:]

    def get_id(self):
        return self.sender[0][-1].get_id()

    def get_transactions(self, start=0, end=2):
        return [(packet[-1].get_seq(), packet[-1].get_ack(), packet[-1].get_window_size() * self.win_scaling) for packet
                in self.flow if packet[-1].get_src() == SENDER][start:end]

    def get_throughput(self):
        # find the fin,ack from receiver
        last_packet = None
        for packet in self.receiver:
            if packet[-1].get_tcp_flags() == 0x11:
                last_packet == packet
        # get index of last packet in flow
        index = self.flow.index(packet)
        flow_in_period = self.flow[:index + 1]
        data_sent = sum([packet[-1].get_tcp_size() for packet in flow_in_period if packet[-1].get_src() == SENDER])
        period = flow_in_period[-1][1] - flow_in_period[0][1]

        return data_sent, period

    def estimate_congestion_window_size(self, num_of_sizes=3):
        # estimate 1 RTT
        # get first ack in from receiver in flow
        first_ack = None
        for packet in self.flow:
            if packet[-1].get_src() == RECEIVER:
                first_ack = packet
                break
        start_time = self.flow[0][1]
        RTT = round(first_ack[1] - start_time, ndigits=6)
        # get timestamps 
        timestamps = [packet[1] for packet in self.flow if packet[-1].get_src() == SENDER]
        # subtract start time from each timestamp
        timestamps = [ts - start_time for ts in timestamps]
        breakpoints = [i * RTT for i in range(1, num_of_sizes + 1)]
        # get estimated window sizes
        win_sizes = []
        timestamp_counter = 0
        for bp in breakpoints:
            breakpoint_counter = 0
            while timestamp_counter < len(timestamps):
                if timestamps[timestamp_counter] > bp:
                    win_sizes.append(breakpoint_counter)
                    break
                breakpoint_counter += 1
                timestamp_counter += 1

        return win_sizes

    def get_retransmission(self):
        # find triple dup acks receive (using ack num)
        receive = Counter([packet[-1].get_ack() for packet in self.flow if packet[-1].get_src() == RECEIVER])
        triple_dups_acks = [ack for ack, count in receive.items() if count > 3]
        # find duplicate acks sent (using seq num)
        sent = Counter([packet[-1].get_seq() for packet in self.flow if packet[-1].get_src() == SENDER])
        duplicate_seqs = [seq for seq, count in sent.items() if count > 1]

        # Ignore dups that are not resent
        intersection = set(duplicate_seqs).intersection(triple_dups_acks)
        out_of_order = 0
        for num in intersection:
            # find the second count in receiver
            first_dup_ack_count = None
            count = 0
            for packet in self.receiver:
                if packet[-1].get_ack() == num:
                    count += 1
                if count == 2:
                    first_dup_ack_count = packet[0]
                    break

            # check that the retransmission is out of order
            count = 0
            for packet in self.sender:
                if packet[-1].get_seq() == num:
                    count += 1
                if count == 2:
                    if first_dup_ack_count > packet[0]:
                        out_of_order += 1
                    break

        triple_dups_count = len(intersection) - out_of_order
        timeout_transmissions = len(duplicate_seqs) - triple_dups_count

        return triple_dups_count, timeout_transmissions


def get_ip(data):
    """
    Returns the IP addresss encode as 4 bytes in as . dot separated string.
    """
    data = data.hex()
    return ".".join([str(int(data[i:i + 2], base=16)) for i in range(0, len(data), 2)])


def get_tcp_flows(file):
    flows = {}
    actual_flows = []
    identifications = []
    counter = 0
    pcap = dpkt.pcap.Reader(file)
    for timestamp, buf in pcap:
        counter += 1
        e = dpkt.ethernet.Ethernet(buf)
        if isinstance(e.data, dpkt.ip.IP):
            ip = e.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src = get_ip(ip.src)
                dst = get_ip(ip.dst)
                if not (str(src) == SENDER and str(dst) == RECEIVER) and not (
                        str(dst) == SENDER and str(src) == RECEIVER):
                    continue

                iden = (tcp.sport, src, tcp.dport, dst)
                print(counter)
                # print(iden)

                # One two-way TCP flow uses one idenP (send->recv)
                idenP = iden if src == SENDER else (tcp.dport, dst, tcp.sport, src)
                if idenP not in identifications:
                    identifications.append(idenP)

                if iden not in flows:
                    flows[iden] = []
                flows[iden].append((counter, timestamp, Packet(buf)))
                # print("flows[iden]: " + str(flows[iden]))

        # Early termination
        # if counter >= 10000:
        #     break

    for src_iden in identifications:
        dest_iden = src_iden[2:] + src_iden[:2]
        actual_flows.append(Flow(flows[src_iden], flows[dest_iden]))

    return actual_flows


if __name__ == "__main__":
    with open(FILE_PATH, 'rb') as f:
        # process_pcap(f)
        result = get_tcp_flows(f)
        print(f"There are a total of {len(result)} TCP flows\n")
        for num, flow in enumerate(result, start=1):
            # print(flow)
            print(f"Flow {num} Information:")
            print("PART A")
            print(f"a) {flow.get_id()}")

            transactions = flow.get_transactions()
            print("b) The first 2 transactions:")
            for t_count, transaction in enumerate(transactions, start=1):
                print(
                    f"Tranaction {t_count}: \n\tSequence number: {transaction[0]:,d}\n\tAck number: {transaction[1]:,d}\n\tReceive Window Size: {transaction[2]:,d}")

            data_sent, period = flow.get_throughput()
            print(
                f"c) Throughput: {data_sent / period:,f} bytes/second ({data_sent:,d} bytes sent in {period:.4f} seconds)")
            print("PART B")
            print(f"1) The first 3 congestion window sizes: {flow.estimate_congestion_window_size()}")
            dup_ack_retransmission, timeout_retransmission = flow.get_retransmission()
            print(
                f"2) \tRetransmission due to triple duplicate ack: {dup_ack_retransmission}\n\tRetransmission due to timeout: {timeout_retransmission}")
            print("=" * 100)
