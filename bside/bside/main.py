#!/usr/bin/env python3
"""B-Side: Binary-Level Static System Call Identification.

CLI entry point for B-Side, a static binary analysis tool that identifies
all possible system calls an x86-64 ELF executable may invoke at runtime.

Based on the paper: arXiv:2410.18053v1
"B-Side: Binary-Level Static System Call Identification"
Thévenon et al., Middleware 2024.

Usage:
    python -m bside.main --binary /path/to/binary [options]

Examples:
    # Analyze a static binary
    python -m bside.main --binary ./my_static_program

    # Analyze a dynamic binary with library processing
    python -m bside.main --binary ./my_dynamic_program --dynamic

    # With phase detection
    python -m bside.main --binary ./my_program --phases

    # JSON output
    python -m bside.main --binary ./my_program --output json
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, Set

from .syscall_table import syscall_name, SYSCALL_TABLE
from .disassembly import disassemble, DisassemblyResult
from .syscall_identification import (
    identify_syscalls, SyscallIdentificationResult,
)
from .shared_library import analyze_dynamic_binary
from .phase_detection import detect_phases, PhaseDetectionResult
from .graph_export import build_syscall_graph

logger = logging.getLogger("bside")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt, stream=sys.stderr)
    # Suppress noisy angr/claripy logging unless verbose
    if not verbose:
        logging.getLogger("angr").setLevel(logging.WARNING)
        logging.getLogger("claripy").setLevel(logging.WARNING)
        logging.getLogger("cle").setLevel(logging.WARNING)
        logging.getLogger("pyvex").setLevel(logging.WARNING)


def is_static_binary(binary_path: str) -> bool:
    """Determine if a binary is statically compiled."""
    try:
        import lief
        binary = lief.parse(binary_path)
        if binary is None:
            return True
        # A statically compiled binary has no NEEDED entries (no shared lib deps)
        return len(list(binary.libraries)) == 0
    except Exception:
        return True  # Default to static if we can't determine


def analyze_static(binary_path: str, timeout: int,
                   do_phases: bool, do_graph: bool = False) -> dict:
    """Analyze a statically compiled binary.

    Args:
        binary_path: Path to the binary.
        timeout: Symbolic execution timeout per site.
        do_phases: Whether to perform phase detection.

    Returns:
        Analysis results as a dictionary.
    """
    start_time = time.time()

    print("=" * 60)
    print("Step 1: Disassembly and CFG Recovery")
    print("=" * 60)
    logger.info("Loading binary and building initial CFG...")
    
    step1_start = time.time()
    disasm = disassemble(binary_path)
    step1_time = time.time() - step1_start
    logger.info("Step 1 completed in %.1f seconds", step1_time)

    # Step 2: System Call Identification
    print("=" * 60)
    print("Step 2: System Call Sites and Type Identification")
    print("=" * 60)
    step2_start = time.time()
    result = identify_syscalls(
        disasm.project, disasm.cfg, disasm.precise_cfg,
        disasm.entry_point, timeout
    )
    step2_time = time.time() - step2_start
    logger.info("Step 2 completed in %.1f seconds", step2_time)

    total_time = time.time() - start_time

    # Build output
    output = {
        "binary": os.path.abspath(binary_path),
        "binary_type": "static",
        "analysis_time_seconds": round(total_time, 2),
        "step_times": {
            "cfg_recovery": round(step1_time, 2),
            "syscall_identification": round(step2_time, 2),
        },
        "cfg_stats": {
            "nodes": disasm.precise_cfg.number_of_nodes(),
            "edges": disasm.precise_cfg.number_of_edges(),
            "active_addresses_taken": len(disasm.active_addr_taken),
            "functions": len(disasm.functions),
        },
        "syscall_sites": len(result.syscall_sites),
        "wrappers_detected": len(result.wrappers),
        "num_syscalls": len(result.all_syscalls),
        "syscalls": [
            {"number": num, "name": syscall_name(num)}
            for num in sorted(result.all_syscalls)
        ],
        "per_site": {
            f"0x{addr:x}": [
                {"number": num, "name": syscall_name(num)}
                for num in sorted(syscalls)
            ]
            for addr, syscalls in result.per_site_syscalls.items()
        },
    }

    # Phase detection
    if do_phases:
        logger.info("=" * 60)
        logger.info("Phase Detection")
        logger.info("=" * 60)
        phase_start = time.time()

        # Build site-to-block mapping
        site_to_block = {}
        for site in result.syscall_sites:
            site_to_block[site.address] = site.block_addr

        # Get block sizes
        block_sizes = {}
        for node in disasm.cfg.graph.nodes():
            if node.block is not None:
                block_sizes[node.addr] = node.size

        phase_result = detect_phases(
            disasm.precise_cfg,
            result.per_site_syscalls,
            site_to_block,
            result.all_syscalls,
            disasm.entry_point,
            block_sizes,
        )
        phase_time = time.time() - phase_start
        logger.info("Phase detection completed in %.1f seconds", phase_time)

        output["phase_detection"] = phase_result.to_dict()
        output["step_times"]["phase_detection"] = round(phase_time, 2)

    # Syscall graph for GNN
    if do_graph:
        logger.info("=" * 60)
        logger.info("Syscall Graph Export (for GNN)")
        logger.info("=" * 60)
        graph_start = time.time()

        site_to_block = {}
        for site in result.syscall_sites:
            site_to_block[site.address] = site.block_addr

        syscall_graph = build_syscall_graph(
            disasm.precise_cfg,
            result.per_site_syscalls,
            site_to_block,
            result.syscall_sites,
        )
        graph_time = time.time() - graph_start
        logger.info("Graph export completed in %.1f seconds", graph_time)

        output["syscall_graph"] = syscall_graph.to_dict()
        output["step_times"]["graph_export"] = round(graph_time, 2)

    return output


def analyze_dynamic(binary_path: str, timeout: int,
                    do_phases: bool, cache_dir: str = None) -> dict:
    """Analyze a dynamically compiled binary with libraries.

    Args:
        binary_path: Path to the binary.
        timeout: Symbolic execution timeout.
        do_phases: Whether to perform phase detection.
        cache_dir: Directory to cache library shared interfaces.

    Returns:
        Analysis results as a dictionary.
    """
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("Analyzing dynamic binary with shared libraries")
    logger.info("=" * 60)

    all_syscalls, interfaces = analyze_dynamic_binary(
        binary_path, timeout, cache_dir
    )

    total_time = time.time() - start_time

    output = {
        "binary": os.path.abspath(binary_path),
        "binary_type": "dynamic",
        "analysis_time_seconds": round(total_time, 2),
        "num_syscalls": len(all_syscalls),
        "syscalls": [
            {"number": num, "name": syscall_name(num)}
            for num in sorted(all_syscalls)
        ],
        "libraries_analyzed": {
            name: {
                "functions_with_syscalls": len([
                    f for f, s in iface.function_syscalls.items() if s
                ]),
                "total_syscalls": len(iface.all_syscalls),
                "wrappers": sorted(iface.wrapper_functions),
            }
            for name, iface in interfaces.items()
        },
    }

    return output


def format_text_output(output: dict) -> str:
    """Format analysis results as human-readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("B-Side Analysis Results")
    lines.append("=" * 60)
    lines.append(f"Binary:     {output['binary']}")
    lines.append(f"Type:       {output['binary_type']}")
    lines.append(f"Time:       {output['analysis_time_seconds']}s")
    lines.append("")

    if 'cfg_stats' in output:
        stats = output['cfg_stats']
        lines.append("CFG Statistics:")
        lines.append(f"  Nodes:              {stats['nodes']}")
        lines.append(f"  Edges:              {stats['edges']}")
        lines.append(f"  Functions:          {stats['functions']}")
        lines.append(f"  Active addr taken:  {stats['active_addresses_taken']}")
        lines.append("")

    lines.append(f"Syscall sites:      {output.get('syscall_sites', 'N/A')}")
    lines.append(f"Wrappers detected:  {output.get('wrappers_detected', 'N/A')}")
    lines.append(f"System calls found: {output['num_syscalls']}")
    lines.append("")
    lines.append("Identified System Calls:")
    lines.append("-" * 40)

    for sc in output['syscalls']:
        lines.append(f"  {sc['number']:>3d}  {sc['name']}")

    # Phase detection
    if 'phase_detection' in output:
        pd = output['phase_detection']
        lines.append("")
        lines.append("=" * 60)
        lines.append("Phase Detection Results")
        lines.append("=" * 60)
        lines.append(f"Phases:      {pd['num_phases']}")
        lines.append(f"DFA states:  {pd['dfa_states']}")
        lines.append("")

        for phase in pd['phases']:
            lines.append(f"Phase {phase['id']}:")
            lines.append(f"  Basic blocks: {phase['num_basic_blocks']}")
            lines.append(f"  Code size:    {phase['code_size_bytes']} bytes")
            lines.append(f"  Allowed syscalls: {phase['num_allowed_syscalls']}")
            if phase['transitions']:
                lines.append(f"  Transitions:")
                for t in phase['transitions']:
                    lines.append(f"    {t['syscall_name']}({t['syscall']}) -> Phase {t['target_phase']}")
            lines.append("")

    # Libraries
    if 'libraries_analyzed' in output:
        lines.append("")
        lines.append("Shared Libraries Analyzed:")
        lines.append("-" * 40)
        for lib_name, lib_info in output['libraries_analyzed'].items():
            lines.append(f"  {lib_name}:")
            lines.append(f"    Functions with syscalls: {lib_info['functions_with_syscalls']}")
            lines.append(f"    Total syscalls: {lib_info['total_syscalls']}")
            if lib_info['wrappers']:
                lines.append(f"    Wrappers: {', '.join(lib_info['wrappers'])}")

    return "\n".join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="B-Side: Binary-Level Static System Call Identification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --binary ./my_program
  %(prog)s --binary ./my_program --dynamic --cache-dir ./cache
  %(prog)s --binary ./my_program --phases --output json
  %(prog)s --binary ./my_program --timeout 120 --verbose
        """,
    )
    parser.add_argument(
        "--binary", "-b", required=True,
        help="Path to the target ELF binary"
    )
    parser.add_argument(
        "--dynamic", "-d", action="store_true",
        help="Force analysis as a dynamic binary (with shared libraries). "
             "Auto-detected if not specified."
    )
    parser.add_argument(
        "--static", "-s", action="store_true",
        help="Force analysis as a static binary. Auto-detected if not specified."
    )
    parser.add_argument(
        "--phases", "-p", action="store_true",
        help="Enable phase detection analysis"
    )
    parser.add_argument(
        "--graph", "-g", action="store_true",
        help="Export syscall transition graph (adjacency matrix) for GNN input"
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=60,
        help="Timeout per symbolic execution search in seconds (default: 60)"
    )
    parser.add_argument(
        "--output", "-o", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output-file", "-f",
        help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "--cache-dir", "-c",
        help="Directory to cache shared library interfaces"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    if not os.path.exists(args.binary):
        logger.error("Binary not found: %s", args.binary)
        sys.exit(1)

    # Determine binary type
    if args.static:
        is_static = True
    elif args.dynamic:
        is_static = False
    else:
        is_static = is_static_binary(args.binary)
        logger.info("Auto-detected binary type: %s",
                     "static" if is_static else "dynamic")

    # Run analysis
    try:
        if is_static:
            output = analyze_static(args.binary, args.timeout, args.phases, args.graph)
        else:
            output = analyze_dynamic(
                args.binary, args.timeout, args.phases, args.cache_dir
            )
    except Exception as e:
        logger.error("Analysis failed: %s", e)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Format output
    if args.output == "json":
        result_str = json.dumps(output, indent=2)
    else:
        result_str = format_text_output(output)

    # Write output
    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(result_str)
        logger.info("Results written to: %s", args.output_file)
    else:
        print(result_str)


if __name__ == "__main__":
    main()
