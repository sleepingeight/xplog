import json
import pandas as pd
import numpy as np
import os
import glob
from collections import defaultdict

# Top syscalls for one-hot encoding
TOP_SYSCALLS = [
    'read', 'write', 'send', 'close', 'socket', 'connect', 'accept4', 
    'openat', 'clone', 'execve', 'open', 'dup', 'dup3', 'bind', 'recv'
]

class ProvenanceGraphExtractor:
    def __init__(self, bside_outputs_dir=None, window_ns=5_000_000_000):
        self.priors = {}
        self.window_ns = window_ns
        if bside_outputs_dir:
            for fpath in glob.glob(os.path.join(bside_outputs_dir, "*.json")):
                name = os.path.basename(fpath).replace(".json", "")
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    self.priors[name] = json.load(f)
        
    def parse_log_line(self, line):
        try:
            line = line.strip()
            if " : " not in line: return None
            json_str = line.split(" : ", 1)[1].strip()
            if json_str.endswith(","): json_str = json_str[:-1]
            return json.loads(json_str)
        except: return None

    def extract_graph_features(self, log_path, labels_path=None, scenario_name=None):
        if not os.path.exists(log_path): return pd.DataFrame()

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            logs = [self.parse_log_line(l) for l in f if l.strip()]
            logs = [l for l in logs if l]

        # 1. Load Provenance Labels (Container PIDs)
        attack_pids = set()
        if labels_path and os.path.exists(labels_path):
            with open(labels_path, 'r') as f:
                for line in f:
                    try:
                        lbl = json.loads(line)
                        if "attack_pid" in lbl:
                            attack_pids.add(lbl["attack_pid"])
                    except: pass

        # 2. Map Container PID -> Host PID using log context
        is_attack_host_pid = set()
        pid_to_ppid_host = {}
        
        for entry in logs:
            ctx = entry.get("event_context", {})
            task = ctx.get("task_context", {})
            hpid = task.get("host_pid")
            hppid = task.get("host_ppid")
            cpid = task.get("pid")
            if hpid and hppid:
                pid_to_ppid_host[hpid] = hppid
            if cpid in attack_pids:
                is_attack_host_pid.add(hpid)

        # Propagate labels
        for _ in range(5):
            for hpid, hppid in pid_to_ppid_host.items():
                if hppid in is_attack_host_pid:
                    is_attack_host_pid.add(hpid)

        # 3. Extract Features with uProv Graph Metrics
        features_list = []
        prior = self.priors.get(scenario_name, {})
        allowed_syscalls = {s['name'] for s in prior.get('syscalls', [])}
        current_seq_lens = defaultdict(int)

        # Window-based graph tracking
        # We'll use a sliding window to calculate holistic features
        for i, entry in enumerate(logs):
            ctx = entry.get("event_context", {})
            task = ctx.get("task_context", {})
            syscall = ctx.get("syscall_name")
            hpid = task.get("host_pid")
            ts = ctx.get("ts")
            
            # Label
            label = 1 if hpid in is_attack_host_pid else 0
            
            # Static Violation
            static_violation = 0
            if scenario_name and allowed_syscalls and syscall not in allowed_syscalls:
                static_violation = 1
            
            current_seq_lens[hpid] += 1
            
            # Holistic Window Features (uProv Section V.B)
            # Find all events in the last self.window_ns
            window_start = ts - self.window_ns
            # For simplicity in this script, we'll just look back 50 events for "density"
            window_logs = logs[max(0, i-50):i+1]
            
            unique_nodes = set()
            unique_edges = set()
            for w_entry in window_logs:
                w_ctx = w_entry.get("event_context", {})
                w_task = w_ctx.get("task_context", {})
                w_hpid = w_task.get("host_pid")
                w_sc = w_ctx.get("syscall_name")
                
                unique_nodes.add(f"proc_{w_hpid}")
                # Destination node logic (File or Socket)
                args = w_entry.get("arguments", {})
                dst = args.get("filename") or args.get("uservaddr") or "io"
                unique_nodes.add(f"res_{dst}")
                unique_edges.add((w_hpid, dst, w_sc))

            feat = {
                "ts": ts,
                "host_pid": hpid,
                "is_attack": label,
                "bside_violation": static_violation,
                "retval": ctx.get("retval", 0),
                "seq_len": min(current_seq_lens[hpid], 10),
                "graph_nodes": len(unique_nodes),
                "graph_edges": len(unique_edges),
                "graph_density": len(unique_edges) / len(unique_nodes) if unique_nodes else 0
            }
            
            # One-Hot
            for sc in TOP_SYSCALLS:
                feat[f"sc_{sc}"] = 1 if syscall == sc else 0
            
            features_list.append(feat)

        return pd.DataFrame(features_list)

if __name__ == "__main__":
    print("μProv-Style Provenance Graph Extractor Ready.")
