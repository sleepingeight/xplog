"""Step 2: System Call Sites and Type Identification.

This module handles:
- Syscall site detection (finding syscall instructions)
- Wrapper detection heuristic (two-phase: use-define chain + symbolic)
- System call type identification via backward BFS + forward symbolic execution

Based on Section 4.4 of the B-Side paper.
"""

import logging
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import angr
import claripy
import networkx as nx

from .syscall_table import is_valid_syscall, syscall_name, MAX_SYSCALL_NUM

logger = logging.getLogger(__name__)

# Timeout for symbolic execution per search (seconds)
DEFAULT_SYMEX_TIMEOUT = 60
# Maximum BFS depth for backward search
DEFAULT_MAX_BFS_DEPTH = 200
# Maximum number of active states in symbolic execution
DEFAULT_MAX_ACTIVE_STATES = 50


class DirectedSearch(angr.exploration_techniques.ExplorationTechnique):
    """Exploration technique to restrict search to a set of guide nodes.

    Used to direct forward symbolic execution towards a syscall site using
    nodes identified during backward BFS.
    """

    def __init__(self, guide_nodes: Set[int], target_addr: int):
        super().__init__()
        self.guide_nodes = guide_nodes
        self.target_addr = target_addr

    def filter(self, simgr, state, **kwargs):
        # We allow the target address and any node in our guide set
        if state.addr == self.target_addr:
            return None
        if state.addr not in self.guide_nodes:
            # Avoid paths that don't lead to our target
            return 'avoid'
        return None


class SyscallSite:
    """Represents a system call invocation site."""

    def __init__(self, address: int, block_addr: int, function_addr: Optional[int],
                 is_wrapper: bool = False, wrapper_param: Optional[str] = None):
        self.address = address          # Address of the syscall instruction
        self.block_addr = block_addr    # Address of the containing basic block
        self.function_addr = function_addr  # Address of the containing function
        self.is_wrapper = is_wrapper    # Whether this site is in a wrapper function
        self.wrapper_param = wrapper_param  # Parameter holding syscall number
        self.identified_syscalls: Set[int] = set()  # Identified system call numbers
        self.call_sites: Set[int] = set()  # Call sites of the wrapper (if wrapper)

    def __repr__(self):
        kind = "wrapper" if self.is_wrapper else "direct"
        syscalls_str = ", ".join(syscall_name(s) for s in sorted(self.identified_syscalls))
        return f"SyscallSite(0x{self.address:x}, {kind}, [{syscalls_str}])"


class SyscallIdentificationResult:
    """Result of the system call identification process."""

    def __init__(self):
        self.syscall_sites: List[SyscallSite] = []
        self.all_syscalls: Set[int] = set()
        self.per_site_syscalls: Dict[int, Set[int]] = {}  # site addr -> syscall set
        self.wrappers: Dict[int, SyscallSite] = {}  # function addr -> site


def find_syscall_sites(project: angr.Project, cfg,
                       precise_cfg: nx.DiGraph,
                       entry_point: int) -> List[SyscallSite]:
    """Find all syscall instruction sites reachable from the entry point (Step F).

    Scans all basic blocks for the x86-64 'syscall' instruction (opcode 0x0F 0x05).

    Args:
        project: angr Project object.
        cfg: CFG analysis result.
        precise_cfg: Precise CFG (networkx DiGraph).
        entry_point: Program entry point.

    Returns:
        List of SyscallSite objects.
    """
    logger.info("Finding syscall sites...")
    sites = []
    reachable = set(precise_cfg.nodes())

    for func_addr, func in cfg.kb.functions.items():
        for block_addr in func.block_addrs_set:
            if block_addr not in reachable:
                continue
            try:
                block = project.factory.block(block_addr)
            except Exception:
                continue

            for insn in block.capstone.insns:
                if insn.mnemonic == 'syscall':
                    site = SyscallSite(
                        address=insn.address,
                        block_addr=block_addr,
                        function_addr=func_addr,
                    )
                    sites.append(site)
                    logger.debug("Found syscall site at 0x%x in function 0x%x",
                                 insn.address, func_addr)

    logger.info("Found %d syscall sites", len(sites))
    return sites


def _check_wrapper_phase1(project: angr.Project, cfg, site: SyscallSite) -> bool:
    """Phase 1 of wrapper detection: use-define chain analysis (fast).

    Search backwards from the syscall site for mov instructions up to the
    function start. Determine if %rax can be resolved to a concrete value.

    Args:
        project: angr Project object.
        cfg: CFG analysis result.
        site: Syscall site to check.

    Returns:
        True if the site MAY be a wrapper (rax not determinable), False if definitely not.
    """
    if site.function_addr is None:
        return True  # Conservative: may be wrapper

    func = cfg.kb.functions.get(site.function_addr)
    if func is None:
        return True

    # Collect all instructions from function start to syscall site
    # in reverse order for backward analysis
    instructions = []
    for block_addr in func.block_addrs_set:
        try:
            block = project.factory.block(block_addr)
        except Exception:
            continue
        for insn in block.capstone.insns:
            if insn.address <= site.address:
                instructions.append(insn)

    instructions.sort(key=lambda i: i.address, reverse=True)

    # Track what defines %rax
    # x86-64 register IDs in capstone
    RAX = 35   # X86_REG_RAX
    EAX = 19   # X86_REG_EAX
    AX = 0     # X86_REG_AX (value depends on capstone version)
    rax_regs = {35, 19}  # RAX, EAX

    # Simple backward tracking of rax through mov instructions
    target_reg = RAX
    for insn in instructions:
        if insn.address >= site.address:
            continue

        if insn.mnemonic in ('mov', 'movl', 'movq', 'movabs'):
            if len(insn.operands) != 2:
                continue

            dst, src = insn.operands[0], insn.operands[1]

            # If dst is rax/eax
            if dst.type == 1 and dst.reg in rax_regs:  # X86_OP_REG
                if src.type == 1:  # X86_OP_REG - register source
                    # rax = <other_reg> - continue tracking the source reg
                    target_reg = src.reg
                    continue
                elif src.type == 3:  # X86_OP_IMM - immediate
                    # rax = immediate -> concrete value, NOT a wrapper
                    return False
                elif src.type == 2:  # X86_OP_MEM - memory
                    # rax = memory -> can't determine, MAY be wrapper
                    return True

        elif insn.mnemonic == 'xor':
            if len(insn.operands) == 2:
                dst, src = insn.operands[0], insn.operands[1]
                if (dst.type == 1 and dst.reg in rax_regs and
                    src.type == 1 and src.reg in rax_regs):
                    # xor rax, rax -> rax = 0 (read syscall), NOT a wrapper
                    return False

    # Could not find a concrete definition -> may be wrapper
    return True


def _check_wrapper_phase2(project: angr.Project, site: SyscallSite,
                          timeout: int = DEFAULT_SYMEX_TIMEOUT) -> Tuple[bool, Optional[str]]:
    """Phase 2 of wrapper detection: symbolic execution confirmation.

    Launch symbolic execution from the function entry to the syscall site.
    If %rax is symbolic at the syscall, confirms the function is a wrapper.

    Args:
        project: angr Project.
        site: Syscall site to check.
        timeout: Symbolic execution timeout in seconds.

    Returns:
        Tuple of (is_wrapper, parameter_holding_syscall_num).
        parameter will be a string like 'rdi', 'rsi', 'stack_0', etc.
    """
    if site.function_addr is None:
        return False, None

    logger.debug("Wrapper Phase 2: symbolic execution 0x%x -> 0x%x",
                 site.function_addr, site.address)

    try:
        # Create a blank state at the function entry
        state = project.factory.blank_state(
            addr=site.function_addr,
            add_options={
                angr.options.SYMBOLIC_INITIAL_VALUES,
                angr.options.ZERO_FILL_UNINITIALIZED_MEMORY,
            }
        )
        simgr = _get_simgr(project, state, timeout=timeout)

        # Make function arguments symbolic
        # x86-64 ABI: rdi, rsi, rdx, rcx, r8, r9, then stack
        arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        arg_symbols = {}
        for i, reg in enumerate(arg_regs):
            sym = claripy.BVS(f'arg_{reg}', 64)
            setattr(state.regs, reg, sym)
            arg_symbols[reg] = sym

        # Also make stack arguments symbolic (for Go-style ABIs)
        # Scan more slots to be robust
        stack_base = state.regs.rsp
        for i in range(8):  # 8 stack slots instead of 4
            offset = 8 + i * 8  # skip return address
            sym = claripy.BVS(f'arg_stack_{i}', 64)
            state.memory.store(stack_base + offset, sym, endness=project.arch.memory_endness)
            arg_symbols[f'stack_{i}'] = sym

        # Run symbolic execution toward the syscall site
        simgr.explore(find=site.address, num_find=1)

        if simgr.found:
            found_state = simgr.found[0]
            rax_val = found_state.regs.rax

            if rax_val.symbolic:
                # rax is symbolic -> this IS a wrapper
                # Determine which argument holds the syscall number
                for reg_name, sym in arg_symbols.items():
                    # Check if rax depends on this argument
                    if sym.variables.intersection(rax_val.variables):
                        logger.info("Wrapper detected at 0x%x, syscall num in %s",
                                    site.function_addr, reg_name)
                        return True, reg_name

                # rax is symbolic but doesn't match any tracked argument
                # Default to rdi (most common in C ABI)
                logger.info("Wrapper detected at 0x%x, syscall num param unknown, defaulting to rdi",
                            site.function_addr)
                return True, 'rdi'
            else:
                # rax is concrete -> NOT a wrapper
                return False, None
        else:
            logger.debug("Symbolic execution did not reach syscall at 0x%x", site.address)
            return False, None

    except Exception as e:
        logger.debug("Wrapper Phase 2 exception: %s", e)
        return False, None


def detect_wrappers(project: angr.Project, cfg,
                    sites: List[SyscallSite],
                    timeout: int = DEFAULT_SYMEX_TIMEOUT) -> None:
    """Detect system call wrappers among the syscall sites (Step G).

    Uses a two-phase heuristic:
    - Phase 1: Fast use-define chain check
    - Phase 2: Symbolic execution confirmation (only if Phase 1 is positive)

    Modifies the SyscallSite objects in place.

    Args:
        project: angr Project.
        cfg: CFG analysis result.
        sites: List of SyscallSite objects.
        timeout: Per-site symbolic execution timeout.
    """
    logger.info("Detecting system call wrappers...")

    # Group sites by function
    func_sites: Dict[int, List[SyscallSite]] = {}
    for site in sites:
        if site.function_addr is not None:
            func_sites.setdefault(site.function_addr, []).append(site)

    wrappers_found = 0
    for func_addr, func_sites_list in func_sites.items():
        for site in func_sites_list:
            # Phase 1: fast check
            if not _check_wrapper_phase1(project, cfg, site):
                continue  # Definitely not a wrapper

            # Phase 2: symbolic confirmation
            is_wrapper, param = _check_wrapper_phase2(project, site, timeout)
            if is_wrapper:
                site.is_wrapper = True
                site.wrapper_param = param
                wrappers_found += 1

                # Find all call sites of this wrapper function
                func = cfg.kb.functions.get(func_addr)
                if func:
                    # Find predecessors (callers) of this function
                    for caller_addr in cfg.kb.functions.callgraph.predecessors(func_addr):
                        site.call_sites.add(caller_addr)

    logger.info("Detected %d wrapper(s)", wrappers_found)


def _identify_syscalls_at_site_non_wrapper(
        project: angr.Project,
        cfg,
        precise_cfg: nx.DiGraph,
        site: SyscallSite,
        timeout: int = DEFAULT_SYMEX_TIMEOUT,
        max_depth: int = DEFAULT_MAX_BFS_DEPTH,
        max_active: int = DEFAULT_MAX_ACTIVE_STATES) -> Set[int]:
    """Identify system calls at a non-wrapper site using backward BFS + forward symex (Step H).

    Algorithm (from paper Section 4.4, Fig. 5):
    1. Start from the syscall basic block
    2. BFS backwards through the CFG to find predecessor nodes
    3. For each predecessor, run forward directed symbolic execution toward the syscall
    4. If %rax is concrete at the syscall, record it; if symbolic, continue BFS
    5. Stop BFS on a path once an immediate-defining node is found

    Args:
        project: angr Project.
        cfg: CFG analysis result.
        precise_cfg: Precise CFG.
        site: Non-wrapper SyscallSite.
        timeout: Symbolic execution timeout.
        max_depth: Maximum BFS depth.
        max_active: Maximum active states in simgr.

    Returns:
        Set of identified system call numbers.
    """
    syscalls = set()
    syscall_block = site.block_addr

    # Build reverse CFG for backward BFS
    reverse_cfg = precise_cfg.reverse()

    # BFS backwards from the syscall block
    bfs_queue = deque([(syscall_block, 0)])  # (node_addr, depth)
    visited = {syscall_block}
    # Track nodes on paths leading to the syscall (for directed symex)
    path_nodes = {syscall_block}
    # Track which predecessors already resolved syscall
    resolved_paths = set()

    while bfs_queue:
        current_addr, depth = bfs_queue.popleft()
        found_concrete = False

        if depth > max_depth:
            continue

        # Fast path: scan the current block for immediate rax assignments
        # This avoiding expensive symex for simple cases (common in library functions)
        try:
            node = project.factory.block(current_addr)
            for insn in reversed(node.capstone.insns):
                # Search for mov rax, <constant> or xor eax, eax
                mnemonic = insn.mnemonic
                op_str = insn.op_str.lower()
                
                if (mnemonic == 'mov' or mnemonic == 'movabs') and ',' in op_str:
                    parts = [p.strip() for p in op_str.split(',')]
                    dst = parts[0]
                    src = parts[1]
                    
                    if dst in ('rax', 'eax', 'rax', 'eax'):
                        # Try to parse src as an integer (dec or hex)
                        val = None
                        try:
                            if src.startswith('0x'):
                                val = int(src, 16)
                            else:
                                val = int(src)
                        except ValueError:
                            pass
                            
                        if val is not None and is_valid_syscall(val):
                            syscalls.add(val)
                            found_concrete = True
                            break
                            
                elif mnemonic == 'xor' and ',' in op_str:
                    parts = [p.strip() for p in op_str.split(',')]
                    if len(parts) == 2 and parts[0] == parts[1]:
                        if parts[0] in ('rax', 'eax'):
                            syscalls.add(0) # read
                            found_concrete = True
                            break
        except Exception:
            pass

        if found_concrete:
            continue

        # Try forward symbolic execution from this predecessor to the syscall site
        if current_addr != syscall_block:
            try:
                concrete_vals = _forward_symex_to_syscall(
                    project, current_addr, site.address,
                    path_nodes, timeout, max_active
                )
                if concrete_vals:
                    for val in concrete_vals:
                        if is_valid_syscall(val):
                            syscalls.add(val)
                            found_concrete = True
                    if found_concrete:
                        resolved_paths.add(current_addr)
            except Exception as e:
                logger.debug("Symex failed from 0x%x: %s", current_addr, e)

        # If we found concrete value(s), don't explore further predecessors on this path
        if found_concrete:
            continue

        # Continue BFS backwards
        if current_addr in reverse_cfg:
            for pred in reverse_cfg.successors(current_addr):
                if pred not in visited:
                    visited.add(pred)
                    path_nodes.add(pred)
                    bfs_queue.append((pred, depth + 1))

    return syscalls


def _identify_syscalls_at_wrapper_site(
        project: angr.Project,
        cfg,
        precise_cfg: nx.DiGraph,
        site: SyscallSite,
        timeout: int = DEFAULT_SYMEX_TIMEOUT,
        max_depth: int = DEFAULT_MAX_BFS_DEPTH,
        max_active: int = DEFAULT_MAX_ACTIVE_STATES) -> Set[int]:
    """Identify system calls at a wrapper site (Step H, wrapper variant).

    For wrappers, we search from each call site of the wrapper function,
    trying to determine the value of the wrapper's parameter that holds
    the syscall number.

    Args:
        project: angr Project.
        cfg: CFG analysis result.
        precise_cfg: Precise CFG.
        site: Wrapper SyscallSite.
        timeout: Symbolic execution timeout.
        max_depth: Maximum BFS depth.
        max_active: Maximum active states.

    Returns:
        Set of identified system call numbers.
    """
    syscalls = set()
    wrapper_func_addr = site.function_addr
    param_name = site.wrapper_param or 'rdi'

    # Determine which register/stack slot to look for
    # x86-64: first arg in rdi, second in rsi, etc.
    abi_reg_map = {
        'rdi': 'rdi', 'rsi': 'rsi', 'rdx': 'rdx',
        'rcx': 'rcx', 'r8': 'r8', 'r9': 'r9',
    }

    # Find all call sites of the wrapper function
    call_sites = set()

    # Look through all functions for calls to the wrapper
    for func_addr, func in cfg.kb.functions.items():
        if func_addr == wrapper_func_addr:
            continue
        for block_addr in func.block_addrs_set:
            if block_addr not in precise_cfg:
                continue
            try:
                block = project.factory.block(block_addr)
            except Exception:
                continue
            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    if len(insn.operands) > 0:
                        op = insn.operands[0]
                        if op.type == 1 and op.imm == wrapper_func_addr:  # X86_OP_IMM
                            call_sites.add(block_addr)

    logger.debug("Wrapper 0x%x has %d call sites", wrapper_func_addr, len(call_sites))

    # For each call site, do backward BFS + forward symex to determine the parameter value
    for call_site_addr in call_sites:
        reverse_cfg = precise_cfg.reverse()
        bfs_queue = deque([(call_site_addr, 0)])
        visited = {call_site_addr}
        path_nodes = {call_site_addr}

        while bfs_queue:
            current_addr, depth = bfs_queue.popleft()
            if depth > max_depth:
                continue

            found_concrete = False
            if current_addr != call_site_addr or depth == 0:
                try:
                    concrete_vals = _forward_symex_to_target(
                        project, current_addr, call_site_addr,
                        param_name, path_nodes, timeout, max_active
                    )
                    if concrete_vals:
                        for val in concrete_vals:
                            if is_valid_syscall(val):
                                syscalls.add(val)
                                found_concrete = True
                except Exception as e:
                    logger.debug("Wrapper symex from 0x%x failed: %s", current_addr, e)

            if found_concrete:
                continue

            if current_addr in reverse_cfg:
                for pred in reverse_cfg.successors(current_addr):
                    if pred not in visited:
                        visited.add(pred)
                        path_nodes.add(pred)
                        bfs_queue.append((pred, depth + 1))

    return syscalls


def _forward_symex_to_syscall(
        project: angr.Project,
        start_addr: int,
        syscall_addr: int,
        guide_nodes: Set[int],
        timeout: int,
        max_active: int) -> List[int]:
    """Run forward directed symbolic execution from start_addr to syscall_addr.

    At the syscall instruction, read the concrete value of %rax.

    Args:
        project: angr Project.
        start_addr: Start address for symbolic execution.
        syscall_addr: Target syscall instruction address.
        guide_nodes: Set of node addresses to guide the exploration.
        timeout: Timeout in seconds.
        max_active: Maximum number of active states.

    Returns:
        List of concrete values found in %rax at the syscall site.
    """
    state = project.factory.blank_state(
        addr=start_addr,
        add_options={
            angr.options.SYMBOLIC_INITIAL_VALUES,
            angr.options.ZERO_FILL_UNINITIALIZED_MEMORY,
        }
    )

    simgr = _get_simgr(project, state, timeout=timeout)
    # Enable directed search using guide nodes
    if guide_nodes:
        simgr.use_technique(DirectedSearch(guide_nodes, syscall_addr))

    try:
        simgr.explore(
            find=syscall_addr,
            num_find=max_active,
        )
    except Exception as e:
        logger.debug("Symex explore exception: %s", e)
        return []

    results = []
    for found_state in simgr.found:
        rax = found_state.regs.rax
        if not rax.symbolic:
            val = found_state.solver.eval(rax)
            if 0 <= val <= MAX_SYSCALL_NUM:
                results.append(val)
        else:
            # Try to enumerate possible concrete values
            try:
                possible_vals = found_state.solver.eval_upto(rax, 50)
                for val in possible_vals:
                    if 0 <= val <= MAX_SYSCALL_NUM:
                        results.append(val)
            except Exception:
                pass

    return results


def _forward_symex_to_target(
        project: angr.Project,
        start_addr: int,
        target_addr: int,
        param_name: str,
        guide_nodes: Set[int],
        timeout: int,
        max_active: int) -> List[int]:
    """Run forward symbolic execution from start_addr to target_addr (wrapper call site).

    At the target, read the value of the specified parameter register/stack slot.

    Args:
        project: angr Project.
        start_addr: Start address.
        target_addr: Target address (wrapper call site).
        param_name: Parameter name to read (e.g., 'rdi', 'stack_0').
        guide_nodes: Guide node set.
        timeout: Timeout in seconds.
        max_active: Maximum active states.

    Returns:
        List of concrete values found in the parameter.
    """
    state = project.factory.blank_state(
        addr=start_addr,
        add_options={
            angr.options.SYMBOLIC_INITIAL_VALUES,
            angr.options.ZERO_FILL_UNINITIALIZED_MEMORY,
        }
    )

    simgr = _get_simgr(project, state, timeout=timeout)
    # Enable directed search using guide nodes
    if guide_nodes:
        simgr.use_technique(DirectedSearch(guide_nodes, target_addr))

    try:
        simgr.explore(find=target_addr, num_find=max_active)
    except Exception as e:
        logger.debug("Wrapper symex exception: %s", e)
        return []

    results = []
    for found_state in simgr.found:
        if param_name.startswith('stack_'):
            # Stack parameter
            idx = int(param_name.split('_')[1])
            offset = 8 + idx * 8  # skip return address
            val_bv = found_state.memory.load(
                found_state.regs.rsp + offset, 8,
                endness=project.arch.memory_endness
            )
        else:
            # Register parameter
            val_bv = getattr(found_state.regs, param_name)

        if not val_bv.symbolic:
            val = found_state.solver.eval(val_bv)
            if 0 <= val <= MAX_SYSCALL_NUM:
                results.append(val)
        else:
            try:
                possible_vals = found_state.solver.eval_upto(val_bv, 50)
                for val in possible_vals:
                    if 0 <= val <= MAX_SYSCALL_NUM:
                        results.append(val)
            except Exception:
                pass

    return results


def identify_syscalls(project: angr.Project, cfg,
                      precise_cfg: nx.DiGraph,
                      entry_point: int,
                      timeout: int = DEFAULT_SYMEX_TIMEOUT,
                      max_depth: int = DEFAULT_MAX_BFS_DEPTH) -> SyscallIdentificationResult:
    """Main entry point for Step 2: System Call Identification.

    Args:
        project: angr Project.
        cfg: CFG analysis result.
        precise_cfg: Precise CFG.
        entry_point: Program entry point.
        timeout: Per-site symbolic execution timeout.
        max_depth: Maximum BFS depth for backward search.

    Returns:
        SyscallIdentificationResult with all identified system calls.
    """
    result = SyscallIdentificationResult()

    # Step F: Find syscall sites
    sites = find_syscall_sites(project, cfg, precise_cfg, entry_point)

    # Step G: Detect wrappers
    detect_wrappers(project, cfg, sites, timeout)

    # Step H: Identify system call types
    logger.info("Identifying system call types at %d sites...", len(sites))

    for i, site in enumerate(sites):
        logger.info("[%d/%d] Processing site 0x%x (%s)...",
                    i + 1, len(sites), site.address,
                    "wrapper" if site.is_wrapper else "direct")

        if site.is_wrapper:
            site_syscalls = _identify_syscalls_at_wrapper_site(
                project, cfg, precise_cfg, site, timeout, max_depth
            )
        else:
            site_syscalls = _identify_syscalls_at_site_non_wrapper(
                project, cfg, precise_cfg, site, timeout, max_depth
            )

        site.identified_syscalls = site_syscalls
        result.all_syscalls.update(site_syscalls)
        result.per_site_syscalls[site.address] = site_syscalls

        if site_syscalls:
            logger.info("  -> Found %d syscall(s): %s",
                        len(site_syscalls),
                        ", ".join(f"{syscall_name(s)}({s})" for s in sorted(site_syscalls)))
        else:
            logger.warning("  -> No syscalls identified at 0x%x", site.address)

        # Record wrappers
        if site.is_wrapper and site.function_addr is not None:
            result.wrappers[site.function_addr] = site

    result.syscall_sites = sites
    logger.info("Total syscalls identified: %d", len(result.all_syscalls))
    return result

def _get_simgr(project: angr.Project, state: angr.SimState, timeout: int):
    """Create a simulation manager with optimized options."""
    # Enable Unicorn if available
    try:
        import unicorn
        state.options.add(angr.options.UNICORN)
        state.options.add(angr.options.UNICORN_SYM_REGS_SUPPORT)
        state.options.add(angr.options.UNICORN_HANDLE_TRANSMIT_SYSCALL)
    except ImportError:
        pass

    # Useful for performance and resolving 'dirty' helpers
    state.options.add(angr.options.REPLACEMENT_SOLVER)

    simgr = project.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.Timeout(timeout=timeout))
    return simgr
