
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon May 12 17:46:13 2025

@author: hallavar
"""
import numpy as np
import pandas as pd
from scipy.spatial import distance
from scipy.stats import entropy
from scapy.all import rdpcap, TCP, UDP, IP, IPv6, ICMP, ARP, Raw

SESSION_TIMEOUT = 120  # seconds

def extract_packet_features_from_packets(packets):
    features = []

    for pkt in packets:
        proto, size, ttl, sport, dport, flags, ts, ip_version = 0, len(pkt), np.nan, 0, 0, 0, pkt.time, 0

        if IP in pkt:
            ip_version = 4
            ttl = pkt[IP].ttl
            proto = pkt[IP].proto
            if TCP in pkt:
                sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = 1
                flags = pkt[ICMP].type + 1000 #avoid collisions with TCP flags
        elif IPv6 in pkt:
            ip_version = 6
            ttl = pkt[IPv6].hlim
            proto = pkt[IPv6].nh
            if TCP in pkt:
                sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, pkt[TCP].flags
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            elif ICMP in pkt:
                proto = 58
                flags = pkt[ICMP].type + 1000
        elif ARP in pkt:
            proto = 0x0806
            flags = pkt[ARP].op + 2000 #avoid collisions with TCP flags

        features.append([
            ip_version, proto, size, ttl,
            sport, dport, int(flags), ts
        ])

    df = pd.DataFrame(features, columns=[
        'ip_version', 'proto', 'size', 'ttl', 
        'sport', 'dport', 'flags', 'time'
    ])
    df['iat'] = pd.to_numeric(df['time'].diff().fillna(0), errors='coerce')
    df.fillna(0, inplace=True)

    return df

def compare_distributions(real, synthetic, field, is_discrete=False):
    real_values = pd.to_numeric(real[field], errors='coerce')
    synthetic_values = pd.to_numeric(synthetic[field], errors='coerce')

    if is_discrete:
        real_values = real_values.astype(str)
        synthetic_values = synthetic_values.astype(str)
        all_values = np.union1d(real_values.unique(), synthetic_values.unique())
        real_hist = real_values.value_counts(normalize=True).reindex(all_values, fill_value=0)
        synthetic_hist = synthetic_values.value_counts(normalize=True).reindex(all_values, fill_value=0)
    else:
        data = np.concatenate([real_values, synthetic_values])
        try:
            bins = np.histogram_bin_edges(data, bins='fd')
            if len(bins) < 11:
                bins = np.linspace(data.min(), data.max(), 20)
        except Exception:
            bins = np.linspace(data.min(), data.max(), 20)

        real_hist, _ = np.histogram(real_values, bins=bins, density=True)
        synthetic_hist, _ = np.histogram(synthetic_values, bins=bins, density=True)

    real_hist += 1e-8
    synthetic_hist += 1e-8

    real_hist /= real_hist.sum()
    synthetic_hist /= synthetic_hist.sum()

    return distance.jensenshannon(real_hist, synthetic_hist, base=2)

def compute_payload_entropy(packets):
    byte_counts = np.zeros(256)

    for pkt in packets:
        if Raw in pkt:
            data = bytes(pkt[Raw])
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            byte_counts += counts

    byte_probs = byte_counts / byte_counts.sum()
    return entropy(byte_probs, base=2)

def session_reconstruction_check(packets):
    raw_sessions = {}

    for pkt in packets:
        if TCP in pkt and (IP in pkt or IPv6 in pkt):
            src = pkt[IP].src if IP in pkt else pkt[IPv6].src
            dst = pkt[IP].dst if IP in pkt else pkt[IPv6].dst
            ip_pair = tuple(sorted([src, dst]))
            port_pair = tuple(sorted([pkt[TCP].sport, pkt[TCP].dport]))
            session_key = (ip_pair, port_pair)
            flags = pkt[TCP].flags
            ts = pkt.time

            if session_key not in raw_sessions:
                raw_sessions[session_key] = []

            raw_sessions[session_key].append({"flags": flags, "ts": ts})

    split_sessions = []
    for session_key, packets in raw_sessions.items():
        packets.sort(key=lambda p: p['ts'])
        current = []
        for i, pkt in enumerate(packets):
            if i == 0 or pkt['ts'] - packets[i - 1]['ts'] <= SESSION_TIMEOUT:
                current.append(pkt)
            else:
                split_sessions.append(current)
                current = [pkt]
        if current:
            split_sessions.append(current)

    total_sessions = len(split_sessions)
    handshakes, teardowns = 0, 0

    for sess in split_sessions:
        flags_list = [p['flags'] for p in sess]
        syn = any(f & 0x02 for f in flags_list)
        syn_ack = any(f & 0x12 == 0x12 for f in flags_list)
        ack = any(f == 0x10 for f in flags_list)
        fin_rst = any(f & 0x01 or f & 0x04 for f in flags_list)

        if syn and syn_ack and ack:
            handshakes += 1
        if fin_rst:
            teardowns += 1

    return {
        "total_sessions": total_sessions,
        "handshake_ratio": handshakes / total_sessions if total_sessions else 0,
        "teardown_ratio": teardowns / total_sessions if total_sessions else 0
    }


def detect_malformed_packets(packets):
    malformed = 0

    for pkt in packets:
        try:
            if IP in pkt and pkt[IP].len != len(pkt[IP].original):
                malformed += 1
            if TCP in pkt and (len(pkt[TCP].payload) + pkt[TCP].dataofs * 4) > len(pkt[TCP]):
                malformed += 1
            if UDP in pkt and pkt[UDP].len != len(pkt[UDP]):
                malformed += 1
        except:
            malformed += 1

    return malformed, len(packets)

def evaluate_pcaps(train_packets, test_packets, syn_packets):
    train_df = extract_packet_features_from_packets(train_packets)
    test_df = extract_packet_features_from_packets(test_packets)
    syn_df = extract_packet_features_from_packets(syn_packets)

    fields = [
        ('ip_version', True), ('proto', True), ('size', False), ('ttl', False),
        ('sport', True), ('dport', True), ('flags', True), ('iat', False)
    ]

    print("\n--- Jensen-Shannon Divergence to Training ---")
    for field, discrete in fields:
        jsd_syn = compare_distributions(train_df, syn_df, field, is_discrete=discrete)
        jsd_test = compare_distributions(train_df, test_df, field, is_discrete=discrete)
        print(f"{field.upper()} | SYN vs TRAIN: {jsd_syn:.4f} | TEST vs TRAIN: {jsd_test:.4f}")

    print("\n--- Payload Byte Entropy ---")
    ent_train = compute_payload_entropy(train_packets)
    ent_test = compute_payload_entropy(test_packets)
    ent_syn = compute_payload_entropy(syn_packets)
    print(f"Train: {ent_train:.4f}, Test: {ent_test:.4f}, Synthetic: {ent_syn:.4f}")

    print("\n--- TCP Session Checks ---")
    print("Train:", session_reconstruction_check(train_packets))
    print("Test:", session_reconstruction_check(test_packets))
    print("Synthetic:", session_reconstruction_check(syn_packets))

    print("\n--- Malformed Packets ---")
    print(f"Train: {detect_malformed_packets(train_packets)}")
    print(f"Test: {detect_malformed_packets(test_packets)}")
    print(f"Synthetic: {detect_malformed_packets(syn_packets)}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python evaluate_pcap.py <synthetic_pcap> <training_pcap> <test_pcap>")
        sys.exit(1)

    syn_packets = rdpcap(sys.argv[1])
    train_packets = rdpcap(sys.argv[2])
    test_packets = rdpcap(sys.argv[3])
    evaluate_pcaps(train_packets, test_packets, syn_packets)