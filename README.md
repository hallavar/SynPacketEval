# SynPacketEval

**SynPacketEval** is a synthetic network traffic evaluation framework designed to assess the realism and diversity of generated PCAP files using both packet-level and flow-level metrics.

This tool allows you to compare a synthetic PCAP to fixed training and test sets, providing interpretable statistical indicators of quality, diversity, coverage, and authenticity.

---

## 📦 Features

- 🧪 **Packet-Level Metrics**:
  - Jensen-Shannon Divergence (JSD)
  - Payload byte entropy
  - TCP session checks (handshake/teardown)
  - Malformed packet detection

- 📊 **Flow-Level Metrics**:
  - Wasserstein Distance (WD), JSD, PCD, CMD
  - DKC (Diversity of Known Clusters)
  - PRDC (Precision and Coverage)
  - Authenticity score via Hamming neighborhood overlap

- 🔁 End-to-end benchmarking from PCAP → metrics

---

## 🚀 Getting Started

### 1. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the evaluation

```bash
python3 pcap_benchmark.py PATH_TO_YOUR_SYNTHETIC_PCAP
```

You can customize:

```bash
python3 pcap_benchmark.py pcaps/syn.pcap \
  --train_pcap pcaps/train.pcap \
  --test_pcap pcaps/test.pcap \
  --num_runs 10 \
  --sample_size 500 \
  --output_dir output_csvs
```

---

## 📁 Directory Structure

```
SynPacketEval/
├── pcap_benchmark.py        # Main entry point
├── evaluate_pcap.py         # Packet-level metrics
├── extract_netflows.py      # NetFlow extraction from PCAP
├── metrics.py               # Flow-level metrics
└── pcaps/                   # Input PCAPs (train, test, syn)
```

---

## 📜 License

MIT License — feel free to use, modify, and contribute!
