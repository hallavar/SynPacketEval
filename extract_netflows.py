#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Apr 29 17:06:15 2025

@author: hallavar
"""

from collections import deque, defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS
import csv
import sys

FLOW_TIMEOUT = 120  # in seconds

#from https://www.stationx.net/common-ports-cheat-sheet/
raw_port_data = {
    "Echo": [7],
    "CHARGEN": [19],
    "FTP-DATA": [20],
    "FTP": [21],
    "SSH/SCP/SFTP": [22],
    "Telnet": [23],
    "SMTP": [25, 465, 587],
    "WINS Replication": [42],
    "WHOIS": [43],
    "TACACS": [49],
    "DNS": [53],
    "DHCP/BOOTP": [67, 68],
    "TFTP": [69],
    "HTTP": [80, 8080],
    "POP3": [110, 995],
    "IMAP": [143, 993],
    "NNTP": [119, 563],
    "NTP": [123],
    "Microsoft RPC": [135, 1025],
    "NetBIOS": [137, 138, 139],
    "SNMP": [161, 162, 10161, 10162],
    "BGP": [179],
    "IRC": [194, 6665, 6666, 6667, 6668, 6669, 6679, 6697],
    "LDAP": [389, 636],
    "HTTPS": [443, 8443],
    "SMB": [445],
    "Syslog": [514],
    "LPD/LPR": [515],
    "RIP": [520, 521],
    "AFP": [548],
    "RTSP": [554],
    "DHCPv6": [546, 547],
    "RADIUS": [1812, 1813],
    "Microsoft SQL Server": [1433],
    "Oracle DB": [1521, 2483, 2484],
    "NFS": [2049],
    "MySQL": [3306],
    "PostgreSQL": [5432],
    "VNC": [5800] + list(range(5900, 6000)),
    "iSCSI": [860, 3260],
    "X11": [6000, 6001],
    "SIP": [5060, 5061],
    "UPnP": [1900, 5000],
    "Redis": [6379],
    "MongoDB": [27017],
    "Kerberos": [88, 464],
    "LDAPs": [636],
    "OpenVPN": [1194],
    "XMPP": [5222, 5223],
    "BitTorrent": list(range(6881, 7000)),
    "Windows Live Messenger": list(range(6891, 6902)),
    "pcAnywhere": [5631, 5632],
    "NetBackup": [13720, 13721],
    "Sub7": [27374],
    "Back Orifice": [31337],
}

# Build a normalized dictionary with port as key and service name as value
WELL_KNOWN_PORTS = {}
for service, ports in raw_port_data.items():
    for port in ports:
        WELL_KNOWN_PORTS[port] = service

WELL_KNOWN_PORTS = dict(sorted(WELL_KNOWN_PORTS.items()))  # Sort by port number

def get_l7_protocol_name(proto_num, sport, dport):
    if proto_num in (6, 17):
        return WELL_KNOWN_PORTS.get(sport, WELL_KNOWN_PORTS.get(dport, "Unknown"))
    return "Unknown"

def categorize_packet_length(length):
    if length <= 128: return 0
    elif length <= 256: return 1
    elif length <= 512: return 2
    elif length <= 1024: return 3
    elif length <= 1514: return 4
    else: return -1  # discard packets > 1514 bytes

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto_num, start_time, client_is_src=True):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = proto_num

        self.client_ip = src_ip if client_is_src else dst_ip
        self.client_port = src_port if client_is_src else dst_port
        self.server_ip = dst_ip if client_is_src else src_ip
        self.server_port = dst_port if client_is_src else src_port

        self.l7_proto = get_l7_protocol_name(proto_num, src_port, dst_port)
        self.start_time = start_time
        self.end_time = start_time

        self.in_bytes = 0
        self.out_bytes = 0
        self.in_pkts = 0
        self.out_pkts = 0

        self.first_in_time = start_time if client_is_src else None
        self.last_in_time = start_time if client_is_src else None
        self.first_out_time = start_time if not client_is_src else None
        self.last_out_time = start_time if not client_is_src else None

        self.tcp_flags = 0
        self.client_flags = 0
        self.server_flags = 0
        self.total_tcp_flag_bits = 0

        self.min_ttl = 255
        self.max_ttl = 0
        self.min_ip_len = float('inf')
        self.max_ip_len = 0
        self.longest_pkt = 0
        self.shortest_pkt = float('inf')

        self.size_bins = [0, 0, 0, 0, 0]
        
        self.max_win_in = 0
        self.max_win_out = 0

        self.retrans_in_bytes = 0
        self.retrans_in_pkts = 0
        self.retrans_out_bytes = 0
        self.retrans_out_pkts = 0

        self.seen_seq_in = set()
        self.seen_seq_out = set()

        self.icmp_type = None
        self.icmp_code = None
        self.dns_query_id = None
        self.dns_query_type = None
        self.dns_ttl_answer = None
        self.ftp_last_code = None

        self.in_times = []
        self.in_bytes_list = []
        self.out_times = []
        self.out_bytes_list = []

    def update(self, pkt, timestamp):
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return  # Skip non-IP packets
    
        self.end_time = timestamp
    
        # --- Extract IP layer ---
        ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src = ip_layer.src
    
        # TTL or Hop Limit
        ttl = getattr(ip_layer, 'ttl', getattr(ip_layer, 'hlim', 255))
        self.min_ttl = min(self.min_ttl, ttl)
        self.max_ttl = max(self.max_ttl, ttl)
    
        # IP Length (for IPv6, approximate)
        ip_len = getattr(ip_layer, 'len', None)
        if ip_len is None and pkt.haslayer(IPv6):
            ip_len = 40 + getattr(ip_layer, 'plen', 0)  # IPv6: header + payload
        self.min_ip_len = min(self.min_ip_len, ip_len or float('inf'))
        self.max_ip_len = max(self.max_ip_len, ip_len or 0)
    
        # Direction
        direction = 'in' if src == self.client_ip else 'out'
        pkt_len = len(pkt)
        
        bin_index = categorize_packet_length(ip_len)
        if bin_index == -1:
            return  # discard packet > 1514
    
        # TCP handling
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            flags = tcp_layer.flags
            try:
                flag_int = int(flags)
            except (TypeError, ValueError):
                flag_map = {'F':0x01, 'S':0x02, 'R':0x04, 'P':0x08, 'A':0x10, 'U':0x20, 'E':0x40, 'C':0x80}
                flag_int = sum(flag_map.get(ch, 0) for ch in flags if isinstance(flags, str))
            self.tcp_flags |= flag_int
            if direction == 'in':
                self.client_flags |= flag_int
                self.max_win_in = max(self.max_win_in, getattr(tcp_layer, 'window', 0))
            else:
                self.server_flags |= flag_int
                self.max_win_out = max(self.max_win_out, getattr(tcp_layer, 'window', 0))
            self.total_tcp_flag_bits += bin(flag_int).count('1')
    
            # Retransmissions
            if hasattr(tcp_layer, 'seq'):
                seq = tcp_layer.seq
                payload_len = len(tcp_layer.payload)
                if direction == 'in':
                    if seq in self.seen_seq_in:
                        self.retrans_in_bytes += payload_len
                        self.retrans_in_pkts += 1
                    else:
                        self.seen_seq_in.add(seq)
                else:
                    if seq in self.seen_seq_out:
                        self.retrans_out_bytes += payload_len
                        self.retrans_out_pkts += 1
                    else:
                        self.seen_seq_out.add(seq)
    
        # ICMP
        if pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            if self.icmp_type is None:
                self.icmp_type = getattr(icmp_layer, 'type', None)
                self.icmp_code = getattr(icmp_layer, 'code', None)
    
        # DNS
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and self.dns_query_id is None:
                self.dns_query_id = dns.id
                if dns.qdcount > 0 and hasattr(dns, 'qd'):
                    self.dns_query_type = getattr(dns.qd, 'qtype', None)
            elif dns.qr == 1 and self.dns_ttl_answer is None and dns.ancount > 0:
                ans = dns.an
                if isinstance(ans, list) and len(ans) > 0:
                    ans = ans[0]
                self.dns_ttl_answer = getattr(ans, 'ttl', None)
    
        # FTP return code (if implemented in your parsing logic)
        if hasattr(pkt, 'ftp_ret_code'):  # You may need to define this elsewhere
            self.ftp_last_code = pkt.ftp_ret_code
    
        # Update flow-level counters
        if direction == 'in':
            self.in_pkts += 1
            self.in_bytes += pkt_len
            self.in_times.append(timestamp)
            self.in_bytes_list.append(pkt_len)
            self.first_in_time = self.first_in_time or timestamp
            self.last_in_time = timestamp
        else:
            self.out_pkts += 1
            self.out_bytes += pkt_len
            self.out_times.append(timestamp)
            self.out_bytes_list.append(pkt_len)
            self.first_out_time = self.first_out_time or timestamp
            self.last_out_time = timestamp
    
        self.longest_pkt = max(self.longest_pkt, pkt_len)
        self.shortest_pkt = min(self.shortest_pkt, pkt_len)
        self.size_bins[bin_index] += 1
    
    def get_duration(self):
        return (self.end_time - self.start_time) * 1000

    def get_duration_in(self):
        if self.first_in_time is None or self.last_in_time is None:
            return 0
        return (self.last_in_time - self.first_in_time) * 1000

    def get_duration_out(self):
        if self.first_out_time is None or self.last_out_time is None:
            return 0
        return (self.last_out_time - self.first_out_time) * 1000

    def compute_throughput(self):
        dur = (self.end_time - self.start_time)
        if dur <= 0:
            avg_in = self.in_bytes * 1000.0
            avg_out = self.out_bytes * 1000.0
        else:
            avg_in = self.in_bytes / dur
            avg_out = self.out_bytes / dur
        return avg_in, avg_out

    def compute_peak_1s_bytes(self):
        def peak_window(timestamps, sizes):
            max_bytes = 0
            window = deque()
            size_sum = 0
            for t, s in zip(timestamps, sizes):
                window.append((t, s))
                size_sum += s
                while window and t - window[0][0] > 1.0:
                    _, sz = window.popleft()
                    size_sum -= sz
                max_bytes = max(max_bytes, size_sum)
            return max_bytes

        return peak_window(self.in_times, self.in_bytes_list), peak_window(self.out_times, self.out_bytes_list)

    def to_csv_record(self):
        flow_duration = self.get_duration()
        dur_in = self.get_duration_in()
        dur_out = self.get_duration_out()
        avg_in, avg_out = self.compute_throughput()
        peak_in, peak_out = self.compute_peak_1s_bytes()
        return (
            self.start_time, self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol, self.l7_proto,
            self.in_bytes, self.out_bytes, self.in_pkts, self.out_pkts,
            flow_duration, self.total_tcp_flag_bits, self.client_flags, self.server_flags,
            dur_in, dur_out,
            0 if self.min_ttl == 255 else self.min_ttl, self.max_ttl,
            self.longest_pkt, 0 if self.shortest_pkt == float('inf') else self.shortest_pkt,
            0 if self.min_ip_len == float('inf') else self.min_ip_len, self.max_ip_len,
            peak_in, peak_out,
            self.retrans_in_bytes, self.retrans_in_pkts, self.retrans_out_bytes, self.retrans_out_pkts,
            int(avg_in), int(avg_out),
            *self.size_bins,
            self.max_win_in, self.max_win_out,
            self.icmp_type or '', self.icmp_code or '',
            self.dns_query_id or '', self.dns_query_type or '', self.dns_ttl_answer or '',
            self.ftp_last_code or ''
        )
# Main logic
def main(input_pcap, output_csv):
    flows_active = defaultdict(list)  # key -> list of Flow objects
    flows_finished = []

    try:
        reader = PcapReader(input_pcap)
    except FileNotFoundError:
        print(f"Input PCAP file '{input_pcap}' not found.")
        sys.exit(1)

    for pkt in reader:
        ip = None
        if pkt.haslayer(IP):
            ip = pkt[IP]
            proto = ip.proto
            src = ip.src
            dst = ip.dst
        elif pkt.haslayer(IPv6):
            ip = pkt[IPv6]
            proto = ip.nh
            src = ip.src
            dst = ip.dst
        else:
            continue  # Skip non-IP packets

        src_port = 0
        dst_port = 0
        if proto == 6 and pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif proto == 17 and pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif proto == 1 and pkt.haslayer(ICMP):
            icmp_layer = pkt[ICMP]
            src_port = icmp_layer.type
            dst_port = icmp_layer.code

        key = (min(src, dst), max(src, dst), min(src_port, dst_port), max(src_port, dst_port), proto)
        direction = 'in' if src < dst else 'out'

        matched = False
        for flow in flows_active[key]:
            if pkt.time - flow.end_time <= FLOW_TIMEOUT:
                flow.update(pkt, pkt.time)
                matched = True
                break

        if not matched:
            client_is_src = direction == 'in'
            new_flow = Flow(src, dst, src_port, dst_port, proto, pkt.time, client_is_src=client_is_src)
            new_flow.update(pkt, pkt.time)
            flows_active[key].append(new_flow)

    reader.close()

    for flow_list in flows_active.values():
        flows_finished.extend(flow_list)

    flows_finished.sort(key=lambda f: f.start_time)

    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "FLOW_START_TIMESTAMP", "IPV4_SRC_ADDR", "IPV4_DST_ADDR", "L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL", "L7_PROTO",
            "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS",
            "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "DURATION_IN", "DURATION_OUT",
            "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
            "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES",
            "RETRANSMITTED_IN_BYTES", "RETRANSMITTED_IN_PKTS", "RETRANSMITTED_OUT_BYTES", "RETRANSMITTED_OUT_PKTS",
            "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
            "NUM_PKTS_UP_TO_128_BYTES", "NUM_PKTS_128_TO_256_BYTES", "NUM_PKTS_256_TO_512_BYTES",
            "NUM_PKTS_512_TO_1024_BYTES", "NUM_PKTS_1024_TO_1514_BYTES",
            "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
            "ICMP_TYPE", "ICMP_IPV4_TYPE", "DNS_QUERY_ID", "DNS_QUERY_TYPE", "DNS_TTL_ANSWER", "FTP_COMMAND_RET_CODE"
        ])
        for flow in flows_finished:
            writer.writerow(flow.to_csv_record())

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        main(sys.argv[1], sys.argv[2])
    else:
        print("Usage: script.py <input.pcap> <output.csv>")