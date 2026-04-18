"""Step 1: Disassembly and CFG Recovery.

This module handles:
- Binary loading via angr
- Initial CFG construction
- Address taken identification (lea instructions)
- Active addresses taken (iterative reachability from entry point)
- Indirect call resolution
- Precise CFG construction

Based on Section 4.3 of the B-Side paper.
"""

import logging
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import angr
import networkx as nx

logger = logging.getLogger(__name__)


class DisassemblyResult:
    """Result of the disassembly and CFG recovery process."""

    def __init__(self, project: angr.Project, cfg, precise_cfg: nx.DiGraph,
                 functions: Dict[int, angr.knowledge_plugins.functions.function.Function],
                 active_addr_taken: Set[int],
                 entry_point: int):
        self.project = project
        self.cfg = cfg  # angr CFG object
        self.precise_cfg = precise_cfg  # networkx DiGraph of basic block addresses
        self.functions = functions
        self.active_addr_taken = active_addr_taken
        self.entry_point = entry_point


def load_binary(binary_path: str, auto_load_libs: bool = False) -> angr.Project:
    """Load a binary using angr.

    Args:
        binary_path: Path to the ELF binary.
        auto_load_libs: Whether to auto-load shared library dependencies.

    Returns:
        angr Project object.
    """
    logger.info("Loading binary: %s", binary_path)
    project = angr.Project(
        binary_path,
        auto_load_libs=auto_load_libs,
    )
    logger.info("Binary loaded: arch=%s, entry=0x%x", project.arch.name, project.entry)
    return project


def build_initial_cfg(project: angr.Project) -> angr.analyses.cfg.CFGFast:
    """Build the initial CFG using angr's CFGFast analysis (Step D).

    Args:
        project: angr Project object.

    Returns:
        CFGFast analysis result.
    """
    logger.info("Building initial CFG with CFGFast...")
    cfg = project.analyses.CFGFast(
        normalize=True,
        force_complete_scan=False,
        resolve_indirect_jumps=True,
        data_references=True,
        symbols=True,
        function_prologues=True,
    )
    num_nodes = len(list(cfg.graph.nodes()))
    num_functions = len(list(cfg.kb.functions))
    logger.info("Initial CFG built: %d nodes, %d functions", num_nodes, num_functions)
    return cfg


def find_addresses_taken(project: angr.Project, cfg) -> Set[int]:
    """Find all addresses taken in the binary (Step E, initial scan).

    An address taken is a code address used as the operand of a lea instruction
    OR found as a pointer in a data section.

    Args:
        project: angr Project object.
        cfg: CFG analysis result.

    Returns:
        Set of addresses taken.
    """
    addresses_taken = set()

    # Find the code segment bounds
    text_min = float('inf')
    text_max = 0
    for obj in project.loader.all_objects:
        for seg in obj.segments:
            if seg.is_executable:
                text_min = min(text_min, seg.min_addr)
                text_max = max(text_max, seg.max_addr)

    if text_min == float('inf'):
        logger.warning("No executable segments found!")
        return addresses_taken

    # Scan all basic blocks for lea instructions
    for node in cfg.graph.nodes():
        if node.block is None:
            continue
        try:
            block = project.factory.block(node.addr, size=node.size)
        except Exception:
            continue

        for insn in block.capstone.insns:
            if insn.mnemonic == 'lea':
                for op in insn.operands:
                    if op.type == 2:  # X86_OP_MEM
                        if op.mem.base == 0 and op.mem.index == 0:
                            addr = op.mem.disp
                        elif op.mem.base == 41:  # X86_REG_RIP
                            addr = insn.address + insn.size + op.mem.disp
                        else:
                            continue
                        if text_min <= addr <= text_max:
                            addresses_taken.add(addr)
                    elif op.type == 1:  # X86_OP_IMM
                        addr = op.imm
                        if text_min <= addr <= text_max:
                            addresses_taken.add(addr)

    # Scan data sections for pointers to code
    # This is crucial for vtables and function pointer arrays (common in SQLite)
    for obj in project.loader.all_objects:
        for sec in obj.sections:
            if not sec.is_executable and (sec.name in ('.data', '.rodata', '.data.rel.ro', '.init_array', '.fini_array')):
                logger.debug("Scanning section %s for addresses taken...", sec.name)
                data = project.loader.memory.load(sec.vaddr, sec.memsize)
                # Assume 8-byte aligned pointers for x86-64
                byteorder = 'little' if 'LE' in project.arch.memory_endness else 'big'
                for i in range(0, len(data) - 7, 8):
                    ptr = int.from_bytes(data[i:i+8], byteorder=byteorder)
                    if text_min <= ptr <= text_max:
                        # Check if it's a known function or looks like one (e.g. 16-byte aligned)
                        if ptr in cfg.kb.functions or ptr % 16 == 0:
                            addresses_taken.add(ptr)

    logger.info("Found %d addresses taken in the binary (code + data)", len(addresses_taken))
    return addresses_taken


def find_reachable_nodes(cfg_graph: nx.DiGraph, entry_addr: int) -> Set[int]:
    """Find all nodes reachable from the entry point in the CFG.

    Args:
        cfg_graph: NetworkX DiGraph of the CFG.
        entry_addr: Entry point address.

    Returns:
        Set of reachable node addresses.
    """
    reachable = set()
    # Find entry node
    entry_node = None
    for node in cfg_graph.nodes():
        addr = node if isinstance(node, int) else node.addr
        if addr == entry_addr:
            entry_node = node
            break

    if entry_node is None:
        logger.warning("Entry point 0x%x not found in CFG", entry_addr)
        return reachable

    # BFS from entry
    queue = deque([entry_node])
    visited = {entry_node}
    while queue:
        current = queue.popleft()
        addr = current if isinstance(current, int) else current.addr
        reachable.add(addr)
        for successor in cfg_graph.successors(current):
            if successor not in visited:
                visited.add(successor)
                queue.append(successor)

    return reachable


def find_active_addresses_taken(project: angr.Project, cfg,
                                all_addr_taken: Set[int],
                                entry_point: int) -> Set[int]:
    """Find active addresses taken: addresses taken reachable from the entry point.

    This is an iterative process as described in the paper (Section 4.3, Fig. 4):
    1. Start with the basic CFG
    2. Find active addresses taken reachable from entry
    3. Update indirect calls to point to all active addresses taken
    4. Repeat until convergence

    Args:
        project: angr Project object.
        cfg: CFG analysis result.
        all_addr_taken: Set of all addresses taken in the binary.
        entry_point: Program entry point address.

    Returns:
        Set of active addresses taken.
    """
    logger.info("Iterative CFG refinement (Active Addresses Taken)...")

    # Pre-compute lea targets for all blocks to avoid re-disassembling
    block_lea_targets: Dict[int, Set[int]] = {}
    indirect_sites: Set[int] = set()

    for node in cfg.graph.nodes():
        if node.block is None:
            continue
        try:
            block = project.factory.block(node.addr, size=node.size)
        except Exception:
            continue

        for insn in block.capstone.insns:
            if insn.mnemonic == 'lea':
                for op in insn.operands:
                    target = None
                    if op.type == 2:  # MEM
                        if op.mem.base == 0 and op.mem.index == 0:
                            target = op.mem.disp
                        elif op.mem.base == 41:  # RIP
                            target = insn.address + insn.size + op.mem.disp
                    elif op.type == 1:  # IMM
                        target = op.imm
                    if target and target in all_addr_taken:
                        block_lea_targets.setdefault(node.addr, set()).add(target)

            if insn.mnemonic in ('call', 'jmp'):
                if len(insn.operands) > 0 and insn.operands[0].type != 1:
                    indirect_sites.add(node.addr)

    # Build local NetworkX graph for fast traversal
    nx_cfg = nx.DiGraph()
    node_map = {}
    for node in cfg.graph.nodes():
        if node.block is not None:
            nx_cfg.add_node(node.addr)
            node_map[node.addr] = node
    for src, dst in cfg.graph.edges():
        if src.block is not None and dst.block is not None:
            nx_cfg.add_edge(src.addr, dst.addr)

    active_addr_taken = set()
    prev_active = set()
    max_iterations = 100
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        # Find reachable blocks from entry
        reachable = nx.descendants(nx_cfg, entry_point) | {entry_point}

        # Find active addresses taken
        active_addr_taken = set()
        for addr in reachable:
            if addr in block_lea_targets:
                active_addr_taken.update(block_lea_targets[addr])

        if active_addr_taken == prev_active:
            logger.info("Active addresses taken converged after %d iterations: %d addresses",
                        iteration, len(active_addr_taken))
            break

        prev_active = active_addr_taken.copy()

        # Update CFG: add edges from indirect sites to active addresses taken
        added_edges = 0
        for site_addr in indirect_sites:
            if site_addr in reachable:
                for target in active_addr_taken:
                    if target in nx_cfg and not nx_cfg.has_edge(site_addr, target):
                        nx_cfg.add_edge(site_addr, target)
                        added_edges += 1

        logger.info("Iteration %d: %d active addresses taken, %d new edges",
                     iteration, len(active_addr_taken), added_edges)

    return active_addr_taken


def build_precise_cfg(project: angr.Project, cfg,
                      active_addr_taken: Set[int],
                      entry_point: int) -> nx.DiGraph:
    """Build the precise CFG by resolving indirect calls with active addresses taken.

    Args:
        project: angr Project object.
        cfg: CFG analysis result.
        active_addr_taken: Set of active addresses taken.
        entry_point: Program entry point.

    Returns:
        NetworkX DiGraph representing the precise CFG.
    """
    logger.info("Building precise CFG...")
    precise_cfg = nx.DiGraph()
    node_map = {}

    # Add all nodes
    for node in cfg.graph.nodes():
        if node.block is not None:
            precise_cfg.add_node(node.addr, size=node.size)
            node_map[node.addr] = node

    # Add all existing edges
    for src, dst in cfg.graph.edges():
        if src.block is not None and dst.block is not None:
            precise_cfg.add_edge(src.addr, dst.addr)

    # Add edges from indirect sites to active addresses taken
    for node in cfg.graph.nodes():
        if node.block is None:
            continue
        try:
            block = project.factory.block(node.addr, size=node.size)
        except Exception:
            continue
        for insn in block.capstone.insns:
            if insn.mnemonic in ('call', 'jmp'):
                if len(insn.operands) > 0 and insn.operands[0].type != 1:
                    for target in active_addr_taken:
                        if target in precise_cfg:
                            precise_cfg.add_edge(node.addr, target)

    # Prune unreachable nodes
    reachable = set()
    if entry_point in precise_cfg:
        queue = deque([entry_point])
        visited = {entry_point}
        while queue:
            current = queue.popleft()
            reachable.add(current)
            for successor in precise_cfg.successors(current):
                if successor not in visited:
                    visited.add(successor)
                    queue.append(successor)

    unreachable = set(precise_cfg.nodes()) - reachable
    precise_cfg.remove_nodes_from(unreachable)

    logger.info("Precise CFG: %d nodes, %d edges (removed %d unreachable)",
                precise_cfg.number_of_nodes(), precise_cfg.number_of_edges(),
                len(unreachable))
    return precise_cfg


def disassemble(binary_path: str, auto_load_libs: bool = False,
                entry_points: Optional[List[int]] = None) -> DisassemblyResult:
    """Main entry point for Step 1: Disassembly and CFG Recovery.

    Args:
        binary_path: Path to the ELF binary/library.
        auto_load_libs: Whether to load shared libraries.
        entry_points: Optional list of entry points (for libraries, use exported functions).

    Returns:
        DisassemblyResult containing the project, CFG, and precise CFG.
    """
    # Step D: Disassembly
    project = load_binary(binary_path, auto_load_libs=auto_load_libs)
    cfg = build_initial_cfg(project)

    # Determine entry point(s)
    ep = project.entry
    if entry_points:
        ep = entry_points[0]  # Primary entry point

    # Step E: CFG Recovery
    all_addr_taken = find_addresses_taken(project, cfg)
    active_addr_taken = find_active_addresses_taken(project, cfg, all_addr_taken, ep)
    precise_cfg = build_precise_cfg(project, cfg, active_addr_taken, ep)

    return DisassemblyResult(
        project=project,
        cfg=cfg,
        precise_cfg=precise_cfg,
        functions=dict(cfg.kb.functions),
        active_addr_taken=active_addr_taken,
        entry_point=ep,
    )
