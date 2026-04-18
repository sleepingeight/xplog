import json
import networkx as nx
import os

class LogReconstructor:
    def __init__(self, bside_cfg_path):
        self.cfg = None
        if os.path.exists(bside_cfg_path):
            with open(bside_cfg_path, 'r') as f:
                self.cfg = json.load(f) # Adjacency list: {syscall: [next_syscalls]}
                # Conver to graph for path finding
                self.G = nx.DiGraph()
                for src, dsts in self.cfg.items():
                    for d in dsts:
                        self.G.add_edge(src, d)

    def reconstruct_gap(self, start_syscall, end_syscall):
        """
        Finds the most likely sequence of syscalls between two points
        using the B-Side static prior.
        """
        if not self.cfg or start_syscall not in self.G or end_syscall not in self.G:
            return []
        
        try:
            # find shortest path in the SC-CFG
            path = nx.shortest_path(self.G, source=start_syscall, target=end_syscall)
            # Remove start/end to get just the missing ones
            return path[1:-1]
        except nx.NetworkXNoPath:
            return []

    def repair_log_stream(self, log_entries):
        """
        Iterates through a stream of logs and identifies causal gaps.
        """
        repaired_stream = []
        for i in range(len(log_entries) - 1):
            curr = log_entries[i]
            nxt = log_entries[i+1]
            
            repaired_stream.append(curr)
            
            # Simple heuristic: if sequential IDs jump, or high timestamp gap
            # we check the SC-CFG for missing transitions.
            curr_name = curr.get("event_context", {}).get("syscall_name")
            next_name = nxt.get("event_context", {}).get("syscall_name")
            
            # Check if transition is valid in SC-CFG
            if self.cfg and next_name not in self.cfg.get(curr_name, []):
                # Gap detected! Try to reconstruct
                missing = self.reconstruct_gap(curr_name, next_name)
                for m in missing:
                    # Inject a "Ghost" entry
                    ghost = {
                        "event_context": {"syscall_name": m, "reconstructed": True},
                        "task_context": curr.get("event_context", {}).get("task_context")
                    }
                    repaired_stream.append(ghost)
                    
        repaired_stream.append(log_entries[-1])
        return repaired_stream

if __name__ == "__main__":
    reconstructor = LogReconstructor("../bside/prior_cfg.json")
    print("Log Reconstruction Engine Ready.")
