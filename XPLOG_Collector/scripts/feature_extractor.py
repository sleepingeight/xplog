import json
import networkx as nx
import pandas as pd
import numpy as np
import os
import glob
from collections import defaultdict

# Top syscalls identified from dataset
TOP_SYSCALLS = [
    'read', 'write', 'send', 'close', 'socket', 'connect', 'accept4', 
    'openat', 'clone', 'execve', 'open', 'dup', 'dup3', 'bind', 'recv'
]

class HybridProvenanceExtractor:
    def __init__(self, bside_outputs_dir=None):
        self.priors = {}
        if bside_outputs_dir:
            for fpath in glob.glob(os.path.join(bside_outputs_dir, "*.json")):
                name = os.path.basename(fpath).replace(".json", "")
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    self.priors[name] = json.load(f)
        
    def parse_log_line(self, line):
        try:
            line = line.strip()
            if " : " not in line: return None
            json_str = line.split(" : ", 1)[1]
            json_str = json_str.strip()
            if json_str.endswith(","):
                json_str = json_str[:-1]
            return json.loads(json_str)
        except:
            return None

    def extract_features(self, log_path, labels_path=None, scenario_name=None):
        if not os.path.exists(log_path):
            return pd.DataFrame()

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            logs = [self.parse_log_line(l) for l in f if l.strip()]
            logs = [l for l in logs if l]

        attack_timestamps = []
        if labels_path and os.path.exists(labels_path):
            with open(labels_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        label = json.loads(line)
                        attack_timestamps.append(label['ts'])
                    except: pass

        prior = self.priors.get(scenario_name, {})
        allowed_syscalls = {s['name'] for s in prior.get('syscalls', [])}

        time_offset = 0
        if logs and "artifacts" in logs[0] and "epoc" in logs[0]["artifacts"]:
            try:
                epoc_ns = int(logs[0]["artifacts"]["epoc"]) * 1000000
                time_offset = epoc_ns - logs[0]["event_context"]["ts"]
            except: pass

        features_list = []
        proc_sequences = defaultdict(list)

        for entry in logs:
            ctx = entry.get("event_context", {})
            task = ctx.get("task_context", {})
            syscall = ctx.get("syscall_name")
            ts = ctx.get("ts")
            host_pid = task.get("host_pid")
            
            synced_ts = ts + time_offset
            
            # Labeling
            is_attack = 0
            if attack_timestamps:
                for ats in attack_timestamps:
                    if abs(synced_ts - ats) < 500000000:
                        is_attack = 1
                        break
            
            # B-Side Prior
            static_violation = 0
            if scenario_name and allowed_syscalls:
                if syscall not in allowed_syscalls:
                    static_violation = 1
            
            # Structural Context
            proc_id = f"{host_pid}_{task.get('task_command')}"
            seq = proc_sequences[proc_id]
            seq.append(syscall)
            if len(seq) > 10: seq.pop(0)

            # Feature Vector Base
            feat = {
                "ts": ts,
                "host_pid": host_pid,
                "is_attack": is_attack,
                "bside_violation": static_violation,
                "retval": ctx.get("retval", 0),
                "seq_len": len(seq),
            }
            
            # One-Hot Encoded Syscalls
            for sc in TOP_SYSCALLS:
                feat[f"sc_{sc}"] = 1 if syscall == sc else 0
            
            features_list.append(feat)

        return pd.DataFrame(features_list)

if __name__ == "__main__":
    print("Hybrid Feature Extractor with One-Hot support ready.")
