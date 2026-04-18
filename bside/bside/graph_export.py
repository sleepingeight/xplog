"""Syscall Graph Export: Extract syscall transition graph for GNN input.

This module bridges B-Side's static analysis with the GNN pipeline by
producing a syscall-to-syscall transition adjacency matrix from the
precise CFG and per-site syscall identification.

The output format matches what the runtime probabilistic model (gen.cpp)
produces, so the GNN can consume both the static graph (from B-Side) and
the dynamic transition matrix (from runtime tracing) in the same format.

Algorithm:
  For each pair of syscall sites (A, B) in the CFG:
    If B is reachable from A without passing through another syscall site:
      For each syscall_num_a in site_A's syscalls:
        For each syscall_num_b in site_B's syscalls:
          adjacency[syscall_num_a][syscall_num_b] = 1
"""

import json
import logging
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from .syscall_table import syscall_name, SYSCALL_TABLE

logger = logging.getLogger(__name__)


class SyscallGraph:
    """Syscall transition graph suitable for GNN consumption."""

    def __init__(self):
        # Set of syscall numbers that appear in the binary
        self.syscall_set: Set[int] = set()
        # Adjacency: (src_syscall, dst_syscall) -> edge weight (path count)
        self.transitions: Dict[Tuple[int, int], int] = {}
        # Node features: syscall_num -> {site_count, is_in_wrapper, ...}
        self.node_features: Dict[int, Dict] = {}

    def add_transition(self, src: int, dst: int, weight: int = 1):
        """Add a transition edge between two syscalls."""
        self.syscall_set.add(src)
        self.syscall_set.add(dst)
        key = (src, dst)
        self.transitions[key] = self.transitions.get(key, 0) + weight

    def get_adjacency_matrix(self) -> Tuple[List[int], List[List[int]]]:
        """Get the adjacency matrix as a 2D list.

        Returns:
            Tuple of (sorted syscall list, NxN adjacency matrix).
        """
        syscalls = sorted(self.syscall_set)
        idx_map = {s: i for i, s in enumerate(syscalls)}
        n = len(syscalls)
        matrix = [[0] * n for _ in range(n)]

        for (src, dst), weight in self.transitions.items():
            if src in idx_map and dst in idx_map:
                matrix[idx_map[src]][idx_map[dst]] = weight

        return syscalls, matrix

    def to_dict(self) -> dict:
        """Serialize to GNN-consumable JSON format.

        Output format:
        {
          "nodes": [{"id": 0, "syscall_num": 1, "syscall_name": "write", ...}, ...],
          "adjacency_matrix": [[0,1,...], ...],
          "edges": [{"src": 0, "dst": 1, "weight": 3}, ...],
          "metadata": {...}
        }
        """
        syscalls, matrix = self.get_adjacency_matrix()
        idx_map = {s: i for i, s in enumerate(syscalls)}

        nodes = []
        for i, sc in enumerate(syscalls):
            node = {
                "id": i,
                "syscall_num": sc,
                "syscall_name": syscall_name(sc),
            }
            if sc in self.node_features:
                node.update(self.node_features[sc])
            nodes.append(node)

        edges = []
        for (src, dst), weight in sorted(self.transitions.items()):
            if src in idx_map and dst in idx_map:
                edges.append({
                    "src": idx_map[src],
                    "dst": idx_map[dst],
                    "src_syscall": syscall_name(src),
                    "dst_syscall": syscall_name(dst),
                    "weight": weight,
                })

        return {
            "num_nodes": len(nodes),
            "num_edges": len(edges),
            "nodes": nodes,
            "adjacency_matrix": matrix,
            "edges": edges,
            "syscall_index": {syscall_name(s): i for i, s in enumerate(syscalls)},
            "metadata": {
                "format": "bside_syscall_graph_v1",
                "description": "Static syscall transition graph from B-Side analysis",
            },
        }

    def save(self, path: str):
        """Save to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("Syscall graph saved to %s", path)

    def to_dot(self) -> str:
        """Convert syscall graph to Graphviz DOT format."""
        lines = [
            'digraph SyscallCFG {',
            '    rankdir=LR;',
            '    node [shape=box, fontname="Courier", style=filled, fillcolor="#f0f0f0"];',
            '    edge [fontname="Courier", fontsize=10];',
            ''
        ]
        
        # Add nodes
        syscalls = sorted(self.syscall_set)
        for sc in syscalls:
            name = syscall_name(sc)
            features = self.node_features.get(sc, {})
            label = f"{name}\\n(count={features.get('site_count', 1)})"
            color = "#ffdddd" if features.get('is_in_wrapper') else "#ddffdd"
            lines.append(f'    sc_{sc} [label="{label}", fillcolor="{color}"];')
        
        lines.append('')
        
        # Add edges
        for (src, dst), weight in sorted(self.transitions.items()):
            label = f"weight={weight}" if weight > 1 else ""
            lines.append(f'    sc_{src} -> sc_{dst} [label="{label}"];')
            
        lines.append('}')
        return "\n".join(lines)

    def save_dot(self, path: str):
        """Save graph to DOT file."""
        with open(path, 'w') as f:
            f.write(self.to_dot())
        logger.info("Syscall DOT graph saved to %s", path)

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Syscall Graph: {len(self.syscall_set)} nodes, {len(self.transitions)} edges",
            "Transitions:",
        ]
        for (src, dst), weight in sorted(self.transitions.items()):
            lines.append(f"  {syscall_name(src):>20s} -> {syscall_name(dst):<20s} (weight={weight})")
        return "\n".join(lines)


def _find_syscall_site_blocks(per_site_syscalls: Dict[int, Set[int]],
                               site_to_block: Dict[int, int]) -> Dict[int, Set[int]]:
    """Map basic block addresses to their syscall sets.

    Args:
        per_site_syscalls: site_addr -> set of syscall nums.
        site_to_block: site_addr -> containing block addr.

    Returns:
        block_addr -> set of syscall nums at that block.
    """
    block_syscalls: Dict[int, Set[int]] = {}
    for site_addr, syscalls in per_site_syscalls.items():
        block_addr = site_to_block.get(site_addr)
        if block_addr is not None and syscalls:
            block_syscalls.setdefault(block_addr, set()).update(syscalls)
    return block_syscalls


def _find_next_syscall_sites(precise_cfg: nx.DiGraph,
                              start_block: int,
                              syscall_blocks: Set[int]) -> Set[int]:
    """BFS from start_block to find the next reachable syscall site blocks.

    Stops at the first syscall block encountered on each path (does not
    traverse through other syscall blocks).

    Args:
        precise_cfg: The precise CFG.
        start_block: Starting block address.
        syscall_blocks: Set of block addresses that contain syscall sites.

    Returns:
        Set of next reachable syscall block addresses.
    """
    next_sites = set()
    visited = {start_block}
    queue = deque()

    # Start BFS from successors of start_block
    if start_block in precise_cfg:
        for succ in precise_cfg.successors(start_block):
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)

    while queue:
        current = queue.popleft()
        if current in syscall_blocks:
            next_sites.add(current)
            # Don't traverse further past this syscall block
            continue

        # Continue BFS through non-syscall blocks
        if current in precise_cfg:
            for succ in precise_cfg.successors(current):
                if succ not in visited:
                    visited.add(succ)
                    queue.append(succ)

    return next_sites


def build_syscall_graph(precise_cfg: nx.DiGraph,
                        per_site_syscalls: Dict[int, Set[int]],
                        site_to_block: Dict[int, int],
                        syscall_sites: list = None) -> SyscallGraph:
    """Build a syscall-to-syscall transition graph from the precise CFG.

    For each syscall site A, finds the next reachable syscall sites B
    (without passing through another syscall site), and creates edges
    from each syscall at A to each syscall at B.

    Args:
        precise_cfg: The precise CFG (networkx DiGraph).
        per_site_syscalls: Per-site syscall mapping.
        site_to_block: Syscall site address -> block address.
        syscall_sites: Optional list of SyscallSite objects (for node features).

    Returns:
        SyscallGraph with syscall transition edges.
    """
    logger.info("Building syscall transition graph...")

    graph = SyscallGraph()

    # Map blocks to their syscall sets
    block_syscalls = _find_syscall_site_blocks(per_site_syscalls, site_to_block)
    syscall_blocks = set(block_syscalls.keys())

    if not syscall_blocks:
        logger.warning("No syscall blocks found, returning empty graph")
        return graph

    # For each syscall block, find the next reachable syscall blocks
    for src_block in syscall_blocks:
        src_syscalls = block_syscalls[src_block]
        next_blocks = _find_next_syscall_sites(precise_cfg, src_block, syscall_blocks)

        for dst_block in next_blocks:
            dst_syscalls = block_syscalls[dst_block]

            # Create edges from each src syscall to each dst syscall
            for src_sc in src_syscalls:
                for dst_sc in dst_syscalls:
                    graph.add_transition(src_sc, dst_sc)

    # Add node features if syscall_sites provided
    if syscall_sites:
        wrapper_syscalls = set()
        site_counts: Dict[int, int] = {}
        for site in syscall_sites:
            for sc in site.identified_syscalls:
                site_counts[sc] = site_counts.get(sc, 0) + 1
                if site.is_wrapper:
                    wrapper_syscalls.add(sc)

        for sc in graph.syscall_set:
            graph.node_features[sc] = {
                "site_count": site_counts.get(sc, 0),
                "is_in_wrapper": sc in wrapper_syscalls,
            }

    logger.info("Syscall graph: %d nodes, %d edges",
                len(graph.syscall_set), len(graph.transitions))
    return graph
