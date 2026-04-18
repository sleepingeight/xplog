"""Step 3: Dynamic Executables and Shared Libraries Processing.

This module handles:
- Library dependency resolution
- Shared interface generation (JSON per library)
- Executable analysis using shared interfaces

Based on Section 4.5 of the B-Side paper.
"""

import json
import logging
import os
import subprocess
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

import angr
import lief
import networkx as nx

from .disassembly import disassemble, DisassemblyResult
from .syscall_identification import (
    identify_syscalls, SyscallIdentificationResult, SyscallSite,
    find_syscall_sites, detect_wrappers,
)
from .syscall_table import syscall_name

logger = logging.getLogger(__name__)


class SharedInterface:
    """Shared interface for a library (Step L in paper Fig. 3).

    Contains metadata mapping exported functions to their system calls.
    """

    def __init__(self, library_path: str):
        self.library_path = library_path
        self.library_name = os.path.basename(library_path)
        # func_name -> set of syscall numbers
        self.function_syscalls: Dict[str, Set[int]] = {}
        # func_name -> list of called external functions
        self.function_external_calls: Dict[str, Set[str]] = {}
        # func_name -> list of addresses taken
        self.function_addr_taken: Dict[str, Set[int]] = {}
        # Set of wrapper function names
        self.wrapper_functions: Set[str] = set()
        # Function-level call graph (func_name -> set of callee names)
        self.call_graph: Dict[str, Set[str]] = {}
        # All syscalls in the library
        self.all_syscalls: Set[int] = set()

    def to_dict(self) -> dict:
        """Serialize to a dictionary."""
        return {
            "library": self.library_name,
            "library_path": self.library_path,
            "functions": {
                name: {
                    "syscalls": sorted(self.function_syscalls.get(name, set())),
                    "external_calls": sorted(self.function_external_calls.get(name, set())),
                    "addresses_taken": sorted(self.function_addr_taken.get(name, set())),
                }
                for name in self.function_syscalls
            },
            "wrappers": sorted(self.wrapper_functions),
            "call_graph": {
                name: sorted(callees)
                for name, callees in self.call_graph.items()
            },
            "all_syscalls": sorted(self.all_syscalls),
        }

    def save(self, output_path: str) -> None:
        """Save the shared interface to a JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("Shared interface saved: %s", output_path)

    @classmethod
    def load(cls, path: str) -> 'SharedInterface':
        """Load a shared interface from a JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)

        si = cls(data.get("library_path", ""))
        si.library_name = data.get("library", "")

        for name, info in data.get("functions", {}).items():
            si.function_syscalls[name] = set(info.get("syscalls", []))
            si.function_external_calls[name] = set(info.get("external_calls", []))
            si.function_addr_taken[name] = set(info.get("addresses_taken", []))

        si.wrapper_functions = set(data.get("wrappers", []))
        si.call_graph = {
            name: set(callees) for name, callees in data.get("call_graph", {}).items()
        }
        si.all_syscalls = set(data.get("all_syscalls", []))
        return si


def get_library_dependencies(binary_path: str) -> List[str]:
    """Get shared library dependencies of a dynamically compiled binary.

    Args:
        binary_path: Path to the ELF binary.

    Returns:
        List of library paths.
    """
    libs = []
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return libs

        for lib_name in binary.libraries:
            # Try to find the library on the system
            lib_path = _find_library(lib_name)
            if lib_path:
                libs.append(lib_path)
            else:
                logger.warning("Library not found: %s", lib_name)
    except Exception as e:
        logger.error("Failed to parse binary for dependencies: %s", e)

    logger.info("Found %d library dependencies for %s", len(libs), binary_path)
    return libs


def _find_library(lib_name: str) -> Optional[str]:
    """Find a shared library on the system.

    Args:
        lib_name: Library name (e.g., 'libc.so.6').

    Returns:
        Full path to the library, or None.
    """
    # Common library paths on Linux
    search_paths = [
        '/lib/x86_64-linux-gnu',
        '/usr/lib/x86_64-linux-gnu',
        '/lib64',
        '/usr/lib64',
        '/lib',
        '/usr/lib',
        '/usr/local/lib',
    ]

    for path in search_paths:
        full_path = os.path.join(path, lib_name)
        if os.path.exists(full_path):
            return full_path

    # Try ldconfig cache
    try:
        result = subprocess.run(
            ['ldconfig', '-p'],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if lib_name in line:
                parts = line.strip().split('=>')
                if len(parts) == 2:
                    path = parts[1].strip()
                    if os.path.exists(path):
                        return path
    except Exception:
        pass

    return None


def get_exported_functions(binary_path: str) -> List[str]:
    """Get the list of exported (public) functions from a shared library.

    Args:
        binary_path: Path to the shared library.

    Returns:
        List of exported function names.
    """
    exported = []
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return exported

        for sym in binary.exported_functions:
            exported.append(sym.name)
    except Exception as e:
        logger.error("Failed to get exported functions: %s", e)

    return exported


def get_imported_functions(binary_path: str) -> Dict[str, str]:
    """Get imported functions and their source libraries.

    Args:
        binary_path: Path to the ELF binary.

    Returns:
        Dict mapping function name to library name.
    """
    imports = {}
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return imports

        for sym in binary.imported_functions:
            # The library providing this function
            if hasattr(sym, 'library') and sym.library:
                imports[sym.name] = sym.library
            else:
                imports[sym.name] = ""
    except Exception as e:
        logger.error("Failed to get imported functions: %s", e)

    return imports


def analyze_library(library_path: str,
                    timeout: int = 60,
                    cache_dir: Optional[str] = None) -> SharedInterface:
    """Analyze a shared library and produce its shared interface (Steps D-H, K, L).

    Args:
        library_path: Path to the shared library (.so).
        timeout: Per-site symbolic execution timeout.
        cache_dir: Directory to cache shared interfaces.

    Returns:
        SharedInterface for the library.
    """
    # Check cache
    if cache_dir:
        cache_path = os.path.join(cache_dir, os.path.basename(library_path) + ".json")
        if os.path.exists(cache_path):
            logger.info("Loading cached shared interface: %s", cache_path)
            return SharedInterface.load(cache_path)

    logger.info("Analyzing library: %s", library_path)
    si = SharedInterface(library_path)

    # Get exported functions
    exported = get_exported_functions(library_path)
    logger.info("Library %s has %d exported functions", library_path, len(exported))

    # Disassemble the library
    try:
        disasm = disassemble(library_path, auto_load_libs=False)
    except Exception as e:
        logger.error("Failed to disassemble library %s: %s", library_path, e)
        return si

    project = disasm.project
    cfg = disasm.cfg

    # Map function addresses to names
    addr_to_name = {}
    name_to_addr = {}
    for func_addr, func in cfg.kb.functions.items():
        if func.name:
            addr_to_name[func_addr] = func.name
            name_to_addr[func.name] = func_addr

    # Run syscall identification on the library
    try:
        syscall_result = identify_syscalls(
            project, cfg, disasm.precise_cfg, disasm.entry_point, timeout
        )
    except Exception as e:
        logger.error("Syscall identification failed for %s: %s", library_path, e)
        return si

    # Build per-function syscall mapping
    # For each exported function, trace its call graph to find reachable syscalls
    func_call_graph = nx.DiGraph()
    for func_addr, func in cfg.kb.functions.items():
        func_name = func.name or f"sub_{func_addr:x}"
        for call_target in cfg.kb.functions.callgraph.successors(func_addr):
            callee = cfg.kb.functions.get(call_target)
            if callee:
                callee_name = callee.name or f"sub_{call_target:x}"
                func_call_graph.add_edge(func_name, callee_name)

    # Map syscall sites to functions
    func_direct_syscalls: Dict[str, Set[int]] = {}
    for site in syscall_result.syscall_sites:
        if site.function_addr and site.function_addr in addr_to_name:
            fname = addr_to_name[site.function_addr]
            func_direct_syscalls.setdefault(fname, set()).update(site.identified_syscalls)

    # For each exported function, compute transitive syscalls
    for func_name in exported:
        reachable_syscalls = set()

        # BFS through call graph
        if func_name in func_call_graph:
            queue = deque([func_name])
            visited = {func_name}
            while queue:
                current = queue.popleft()
                if current in func_direct_syscalls:
                    reachable_syscalls.update(func_direct_syscalls[current])
                for callee in func_call_graph.successors(current):
                    if callee not in visited:
                        visited.add(callee)
                        queue.append(callee)
        else:
            # Just check direct syscalls
            if func_name in func_direct_syscalls:
                reachable_syscalls = func_direct_syscalls[func_name]

        si.function_syscalls[func_name] = reachable_syscalls
        si.all_syscalls.update(reachable_syscalls)

        # Record external calls
        external_calls = set()
        if func_name in func_call_graph:
            for callee in func_call_graph.successors(func_name):
                if callee not in name_to_addr:  # External symbol
                    external_calls.add(callee)
        si.function_external_calls[func_name] = external_calls

    # Record wrappers
    for func_addr, wrapper_site in syscall_result.wrappers.items():
        if func_addr in addr_to_name:
            si.wrapper_functions.add(addr_to_name[func_addr])

    # Build call graph
    for func_name in exported:
        if func_name in func_call_graph:
            si.call_graph[func_name] = set(func_call_graph.successors(func_name))

    # Cache result
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        si.save(cache_path)

    return si


def analyze_dynamic_binary(binary_path: str,
                           timeout: int = 60,
                           cache_dir: Optional[str] = None) -> Tuple[Set[int], Dict[str, SharedInterface]]:
    """Analyze a dynamically compiled binary with its shared libraries (Step 3).

    Args:
        binary_path: Path to the dynamically compiled ELF binary.
        timeout: Per-site symbolic execution timeout.
        cache_dir: Directory to cache shared interfaces.

    Returns:
        Tuple of (all system calls, dict of library shared interfaces).
    """
    logger.info("Analyzing dynamic binary: %s", binary_path)

    all_syscalls = set()
    interfaces: Dict[str, SharedInterface] = {}

    # Step 1 & 2: Analyze the main binary itself
    logger.info("Analyzing main binary...")
    disasm = disassemble(binary_path, auto_load_libs=False)
    main_result = identify_syscalls(
        disasm.project, disasm.cfg, disasm.precise_cfg, disasm.entry_point, timeout
    )
    all_syscalls.update(main_result.all_syscalls)

    # Get library dependencies
    libs = get_library_dependencies(binary_path)

    # Get imported functions (Step J)
    imports = get_imported_functions(binary_path)
    logger.info("Binary imports %d functions", len(imports))

    # Analyze each library (Step K)
    for lib_path in libs:
        logger.info("Analyzing library dependency: %s", lib_path)
        try:
            si = analyze_library(lib_path, timeout, cache_dir)
            interfaces[si.library_name] = si
        except Exception as e:
            logger.error("Failed to analyze library %s: %s", lib_path, e)

    # Step M: Combine binary's imported functions with library interfaces
    for func_name, lib_name in imports.items():
        # Find which library provides this function
        for iface_name, iface in interfaces.items():
            if func_name in iface.function_syscalls:
                func_syscalls = iface.function_syscalls[func_name]
                all_syscalls.update(func_syscalls)
                logger.debug("Import %s from %s: syscalls %s",
                             func_name, iface_name,
                             [syscall_name(s) for s in func_syscalls])
                break

    logger.info("Total syscalls for dynamic binary: %d", len(all_syscalls))
    return all_syscalls, interfaces
