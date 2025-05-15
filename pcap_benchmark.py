#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu May 15 17:20:22 2025

@author: hallavar
"""

import os
import argparse
import subprocess

# ==== SCRIPT FILES ====
EXTRACT_NETFLOWS = "extract_netflows.py"
EVALUATE_PCAP = "evaluate_pcap.py"
METRICS = "metrics.py"
# =======================

def extract_flows(pcap_path, output_csv):
    print(f"\n[+] Extracting NetFlows from {pcap_path} to {output_csv}")
    subprocess.run(["python3", EXTRACT_NETFLOWS, pcap_path, output_csv], check=True)

def run_packet_level_metrics(syn_pcap, train_pcap, test_pcap):
    print("\n=== Running Packet-Level Metrics ===")
    subprocess.run([
        "python3", EVALUATE_PCAP,
        syn_pcap, train_pcap, test_pcap
    ], check=True)

def run_flow_level_metrics(syn_pcap_csv, num_runs, sample_size):
    print("\n=== Running Flow-Level Metrics ===")
    subprocess.run([
        "python3", METRICS,
        syn_pcap_csv, str(num_runs), str(sample_size)
    ], check=True)

def main():
    parser = argparse.ArgumentParser(description="Evaluate synthetic PCAP file using packet and flow-level metrics.")
    parser.add_argument("synthetic_pcap", help="Path to synthetic PCAP file")
    parser.add_argument("--train_pcap", default="pcaps/train.pcap", help="Path to training PCAP file (default: train.pcap)")
    parser.add_argument("--test_pcap", default="pcaps/test.pcap", help="Path to testing PCAP file (default: test.pcap)")
    parser.add_argument("--num_runs", type=int, default=5, help="Number of sampling runs (default: 5)")
    parser.add_argument("--sample_size", type=int, default=1000, help="Sample size for metrics (default: 1000)")
    parser.add_argument("--output_dir", default="output_csvs", help="Output directory for flow CSVs (default: output_csvs)")
    args = parser.parse_args()

    # Create output directory if needed
    os.makedirs(args.output_dir, exist_ok=True)

    # Derive synthetic CSV filename
    syn_csv = os.path.splitext(os.path.basename(args.synthetic_pcap))[0] + ".csv"
    syn_csv_path = os.path.join(args.output_dir, syn_csv)

    # Fixed names for train and test flow CSVs
    train_csv = os.path.join(args.output_dir, "train.csv")
    test_csv = os.path.join(args.output_dir, "test.csv")

    # Step 1: Extract flow-level CSVs from PCAPs
    extract_flows(args.train_pcap, train_csv)
    extract_flows(args.test_pcap, test_csv)
    extract_flows(args.synthetic_pcap, syn_csv_path)

    # Step 2: Run packet-level metrics
    run_packet_level_metrics(args.synthetic_pcap, args.train_pcap, args.test_pcap)

    # Step 3: Run flow-level metrics
    run_flow_level_metrics(syn_csv, args.num_runs, args.sample_size)

if __name__ == "__main__":
    main()
