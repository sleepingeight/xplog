"""Phase Detection: Automaton-based execution phase identification.

This module handles:
- NFA construction from CFG + syscall sites
- NFA → DFA transformation (powerset construction)
- Phase merging (highly-connected states)
- Back-propagation of allowed syscalls

Based on Section 4.7 of the B-Side paper.
"""

import logging
from collections import deque
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

import networkx as nx

from .syscall_table import syscall_name

logger = logging.getLogger(__name__)


class Phase:
    """Represents an execution phase in the program."""

    def __init__(self, phase_id: int, states: FrozenSet[int]):
        self.phase_id = phase_id
        self.states = states  # Set of basic block addresses in this phase
        self.allowed_syscalls: Set[int] = set()  # Syscalls allowed in this phase
        self.transitions: Dict[int, int] = {}  # syscall_num -> target phase_id
        self.code_size: int = 0  # Total size of basic blocks in bytes

    def __repr__(self):
        return (f"Phase({self.phase_id}, states={len(self.states)}, "
                f"syscalls={len(self.allowed_syscalls)}, "
                f"size={self.code_size}B)")


class PhaseDetectionResult:
    """Result of phase detection analysis."""

    def __init__(self):
        self.phases: List[Phase] = []
        self.initial_phase_id: int = 0
        self.total_syscalls: int = 0
        # DFA states and transitions for debugging
        self.dfa_states: int = 0
        self.dfa_transitions: int = 0

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "num_phases": len(self.phases),
            "total_syscalls": self.total_syscalls,
            "initial_phase": self.initial_phase_id,
            "dfa_states": self.dfa_states,
            "dfa_transitions": self.dfa_transitions,
            "phases": [
                {
                    "id": p.phase_id,
                    "num_basic_blocks": len(p.states),
                    "code_size_bytes": p.code_size,
                    "num_allowed_syscalls": len(p.allowed_syscalls),
                    "allowed_syscalls": [
                        {"num": s, "name": syscall_name(s)}
                        for s in sorted(p.allowed_syscalls)
                    ],
                    "transitions": [
                        {"syscall": s, "syscall_name": syscall_name(s),
                         "target_phase": t}
                        for s, t in sorted(p.transitions.items())
                    ],
                }
                for p in self.phases
            ],
        }


def build_nfa(precise_cfg: nx.DiGraph,
              per_site_syscalls: Dict[int, Set[int]],
              site_to_block: Dict[int, int]) -> Tuple[nx.DiGraph, int]:
    """Build an NFA from the CFG and syscall identification results.

    The NFA is constructed by:
    - For each CFG edge leaving a node with a syscall site: label the edge with
      the set of syscalls at that site
    - All other edges become ε-transitions (labeled None)

    Args:
        precise_cfg: Precise CFG (networkx DiGraph of basic block addresses).
        per_site_syscalls: Mapping of syscall site address -> set of syscall numbers.
        site_to_block: Mapping of syscall site address -> containing block address.

    Returns:
        Tuple of (NFA graph with labeled edges, start state).
    """
    logger.info("Building NFA from CFG...")

    # Map block addresses to their syscall sets
    block_syscalls: Dict[int, Set[int]] = {}
    for site_addr, syscalls in per_site_syscalls.items():
        block_addr = site_to_block.get(site_addr)
        if block_addr is not None:
            block_syscalls.setdefault(block_addr, set()).update(syscalls)

    nfa = nx.MultiDiGraph()

    # Add all nodes
    for node in precise_cfg.nodes():
        nfa.add_node(node)

    # Add edges with labels
    for src, dst in precise_cfg.edges():
        if src in block_syscalls:
            # This node has syscall sites - label outgoing edges with syscalls
            for syscall_num in block_syscalls[src]:
                nfa.add_edge(src, dst, label=syscall_num)
        else:
            # ε-transition
            nfa.add_edge(src, dst, label=None)

    num_epsilon = sum(1 for _, _, d in nfa.edges(data=True) if d.get('label') is None)
    num_labeled = sum(1 for _, _, d in nfa.edges(data=True) if d.get('label') is not None)
    logger.info("NFA: %d states, %d ε-transitions, %d labeled transitions",
                nfa.number_of_nodes(), num_epsilon, num_labeled)

    return nfa, list(precise_cfg.nodes())[0] if precise_cfg.nodes() else 0


def epsilon_closure(nfa: nx.MultiDiGraph, states: FrozenSet[int]) -> FrozenSet[int]:
    """Compute the ε-closure of a set of NFA states.

    Args:
        nfa: NFA graph.
        states: Set of state addresses.

    Returns:
        ε-closure as a frozenset.
    """
    closure = set(states)
    queue = deque(states)

    while queue:
        current = queue.popleft()
        if current not in nfa:
            continue
        for _, dst, data in nfa.edges(current, data=True):
            if data.get('label') is None and dst not in closure:
                closure.add(dst)
                queue.append(dst)

    return frozenset(closure)


def nfa_to_dfa(nfa: nx.MultiDiGraph, start_state: int,
               all_syscalls: Set[int]) -> Tuple[nx.DiGraph, FrozenSet[int]]:
    """Transform an NFA into a DFA using the powerset construction algorithm.

    Args:
        nfa: NFA graph with labeled edges.
        start_state: NFA start state.
        all_syscalls: Set of all syscall numbers (the input alphabet).

    Returns:
        Tuple of (DFA graph, DFA start state as frozenset).
    """
    logger.info("Converting NFA to DFA (powerset construction)...")

    dfa = nx.DiGraph()

    # Start state is the ε-closure of the NFA start state
    start_closure = epsilon_closure(nfa, frozenset([start_state]))
    dfa.add_node(start_closure)

    queue = deque([start_closure])
    visited = {start_closure}

    transitions_added = 0
    max_states = 10000  # Safety limit to prevent explosion

    while queue and len(visited) < max_states:
        current_states = queue.popleft()

        for syscall_num in all_syscalls:
            # Find all states reachable via this syscall from current_states
            next_states = set()
            for state in current_states:
                if state not in nfa:
                    continue
                for _, dst, data in nfa.edges(state, data=True):
                    if data.get('label') == syscall_num:
                        next_states.add(dst)

            if not next_states:
                continue

            # Compute ε-closure of the next states
            next_closure = epsilon_closure(nfa, frozenset(next_states))

            if next_closure not in visited:
                visited.add(next_closure)
                dfa.add_node(next_closure)
                queue.append(next_closure)

            dfa.add_edge(current_states, next_closure, syscall=syscall_num)
            transitions_added += 1

    logger.info("DFA: %d states, %d transitions (from %d NFA states)",
                dfa.number_of_nodes(), transitions_added, nfa.number_of_nodes())

    return dfa, start_closure


def merge_phases(dfa: nx.DiGraph, start_state: FrozenSet[int],
                 connectivity_threshold: float = 0.5) -> List[Phase]:
    """Merge highly-connected DFA states into phases.

    States that are highly connected (many transitions between them) are
    merged into a single phase. Each phase has a set of allowed syscalls.

    Args:
        dfa: DFA graph.
        start_state: DFA start state.
        connectivity_threshold: Threshold for merging (0-1).

    Returns:
        List of Phase objects.
    """
    logger.info("Merging DFA states into phases...")

    # Simple approach: use connected components or community detection
    # For now, each DFA state becomes a phase
    phases = []
    state_to_phase: Dict[FrozenSet[int], int] = {}

    for i, state in enumerate(dfa.nodes()):
        phase = Phase(phase_id=i, states=state)
        state_to_phase[state] = i

        # Collect allowed syscalls (outgoing transitions from this state)
        for _, dst, data in dfa.edges(state, data=True):
            syscall_num = data.get('syscall')
            if syscall_num is not None:
                phase.allowed_syscalls.add(syscall_num)

        phases.append(phase)

    # Set up transitions between phases
    for src, dst, data in dfa.edges(data=True):
        syscall_num = data.get('syscall')
        if syscall_num is not None:
            src_phase = state_to_phase.get(src)
            dst_phase = state_to_phase.get(dst)
            if src_phase is not None and dst_phase is not None:
                phases[src_phase].transitions[syscall_num] = dst_phase

    # Try to merge highly-connected phases
    # Two phases are highly connected if they share many transitions
    merged = True
    while merged:
        merged = False
        for i, p1 in enumerate(phases):
            if p1 is None:
                continue
            for j, p2 in enumerate(phases):
                if j <= i or p2 is None:
                    continue

                # Count transitions between p1 and p2
                transitions_between = 0
                total_transitions = len(p1.transitions) + len(p2.transitions)

                for syscall, target in p1.transitions.items():
                    if target == p2.phase_id:
                        transitions_between += 1
                for syscall, target in p2.transitions.items():
                    if target == p1.phase_id:
                        transitions_between += 1

                if total_transitions > 0:
                    ratio = transitions_between / total_transitions
                    if ratio > connectivity_threshold:
                        # Merge p2 into p1
                        new_states = frozenset(set(p1.states) | set(p2.states))
                        p1.states = new_states
                        p1.allowed_syscalls |= p2.allowed_syscalls
                        # Update transitions
                        for syscall, target in p2.transitions.items():
                            if target == p2.phase_id:
                                p1.transitions[syscall] = p1.phase_id
                            else:
                                p1.transitions[syscall] = target
                        phases[j] = None
                        merged = True

    # Remove None entries and re-index
    phases = [p for p in phases if p is not None]
    for i, p in enumerate(phases):
        p.phase_id = i

    logger.info("Merged into %d phases", len(phases))
    return phases


def back_propagate_syscalls(phases: List[Phase]) -> None:
    """Back-propagate authorized syscalls to predecessor phases.

    For seccomp compatibility, a phase must allow all syscalls that
    are allowed in any phase reachable from it.

    Args:
        phases: List of Phase objects (modified in place).
    """
    logger.info("Back-propagating syscalls to predecessor phases...")

    # Build phase graph
    phase_graph = nx.DiGraph()
    for p in phases:
        phase_graph.add_node(p.phase_id)
        for syscall, target in p.transitions.items():
            phase_graph.add_edge(p.phase_id, target)

    # Phase dict for quick lookup
    phase_dict = {p.phase_id: p for p in phases}

    # For each phase, add all syscalls reachable from it
    changed = True
    while changed:
        changed = False
        for phase in phases:
            for _, target_id in phase.transitions.items():
                target_phase = phase_dict.get(target_id)
                if target_phase:
                    before = len(phase.allowed_syscalls)
                    phase.allowed_syscalls |= target_phase.allowed_syscalls
                    if len(phase.allowed_syscalls) > before:
                        changed = True


def detect_phases(precise_cfg: nx.DiGraph,
                  per_site_syscalls: Dict[int, Set[int]],
                  site_to_block: Dict[int, int],
                  all_syscalls: Set[int],
                  entry_point: int,
                  block_sizes: Dict[int, int] = None,
                  do_back_propagation: bool = True) -> PhaseDetectionResult:
    """Main entry point for phase detection analysis.

    Args:
        precise_cfg: Precise CFG.
        per_site_syscalls: Per-site syscall mapping.
        site_to_block: Syscall site to block address mapping.
        all_syscalls: Set of all identified syscalls.
        entry_point: Program entry point.
        block_sizes: Optional mapping of block addresses to sizes.
        do_back_propagation: Whether to do back-propagation (for seccomp).

    Returns:
        PhaseDetectionResult.
    """
    result = PhaseDetectionResult()

    if not all_syscalls:
        logger.warning("No syscalls to detect phases for")
        return result

    # Build NFA
    nfa, nfa_start = build_nfa(precise_cfg, per_site_syscalls, site_to_block)

    # Convert to DFA
    dfa, dfa_start = nfa_to_dfa(nfa, entry_point, all_syscalls)
    result.dfa_states = dfa.number_of_nodes()
    result.dfa_transitions = dfa.number_of_edges()

    # Merge into phases
    phases = merge_phases(dfa, dfa_start)

    # Compute code sizes
    if block_sizes:
        for phase in phases:
            phase.code_size = sum(
                block_sizes.get(addr, 0)
                for addr in phase.states
                if isinstance(addr, int)
            )

    # Back-propagation
    if do_back_propagation:
        back_propagate_syscalls(phases)

    result.phases = phases
    result.total_syscalls = len(all_syscalls)
    if phases:
        result.initial_phase_id = phases[0].phase_id

    return result
