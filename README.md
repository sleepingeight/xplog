# XPLOG: Distributed Provenance Logging and Attack Detection

XPLOG is a high-fidelity distributed logging framework designed for microservice architectures. It leverages eBPF for low-overhead syscall tracing and constructs causal provenance graphs to detect Advanced Persistent Threats (APTs) with high sensitivity and zero false alarms.

## 1. Project Components

- **Attack Emulators** (`dataset/`): Five Go-based containers simulating real-world exploits (SQLi, Reverse Shell, Path Traversal, Data Exfiltration, and Cryptominer Dropper).
- **XPLOG Collector**: A central server that aggregates causally-ordered logs from distributed agents.
- **B-Side Integration**: A static binary analysis tool that provides syscall-level control flow priors.
- **ML Pipeline**: A Graph Convolutional Network (GCN) that performs causal inference and scenario-level detection.

---

## 2. Setup and Installation

### 2.1 Prerequisites
- **OS**: Linux (kernel 5.4+ for eBPF support)
- **Languages**: Go (1.20+), Python (3.10+), Node.js (16+)
- **Tools**: Docker, Docker Swarm (optional)

### 2.2 Environment Setup
```bash
# Clone the repository
git clone <repo_url>
cd xplog

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install torch torch-geometric pandas scikit-learn numpy
```

---

## 3. Operational Guide

### Step 1: Build the Attack Emulators
Each emulator must be compiled to a Go binary to allow B-Side static analysis.
```bash
cd dataset/01_sqli_cmd_exec
go build -o emulator_sqli main.go
# Repeat for other scenarios (02_reverse_shell, etc.)
```

### Step 2: Extract Static Priors (B-Side)
Run B-Side on the generated binaries to create the syscall "Safe List."
```bash
# Note: Ensure B-Side toolkit is in your PATH
./scripts/run_bside.sh ./dataset/01_sqli_cmd_exec/emulator_sqli
# This generates .json files in bside_outputs/
```

### Step 3: Collect Runtime Logs
Start the XPLOG server and run the emulators for ~60 seconds to generate the training dataset.
```bash
# Start XPLOG Server
PYTHONPATH=. python3 XPLOG_Collector/server.py

# In another terminal, run an emulator
./dataset/01_sqli_cmd_exec/emulator_sqli --mode attack --duration 60s
```

### Step 4: Feature Extraction
Convert the raw JSON logs into provenance-enriched feature sets.
```bash
# Using the μProv-style graph extractor
PYTHONPATH=. python3 XPLOG_Collector/scripts/feature_extractor_v2.py
# Output: datasets/full_features_v3_graph.csv
```

### Step 5: Model Training
Train the GCN model on the causal provenance graphs.
```bash
PYTHONPATH=. python3 XPLOG_Collector/scripts/train_detector.py
# Output: models/gnn_detector_v3.pt
```

---

## 4. Detection Engine
The detection suite uses a **Scenario Aggregator** to provide production-level alerting.

- **Fidelity Check**: The aggregator uses a 5-second sliding window to identify sustained clusters of anomalies.
- **Hybrid Filter**: Alerts are prioritized if the GNN anomaly is also a B-Side static violation.

To run a final evaluation on your dataset:
```bash
PYTHONPATH=. python3 XPLOG_Collector/scripts/benchmark_suite_v3.py
```

---

## 5. Contact & Citation
This project is part of a Bachelor of Technology (BTP) thesis at **IIT Kharagpur**.
**Author**: Mamidi Surya Teja
**Supervisor**: Dr. Sandip Chakraborty
