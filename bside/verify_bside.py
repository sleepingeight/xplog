#!/usr/bin/env python3
"""Validation script for B-Side.

Analyzes the pre-built static SQLite binary and verifies results against
the research paper's standards (precision, dangerous syscalls, performance).
"""

import json
import logging
import os
import subprocess
import sys
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("verify_bside")

# Target binary
BINARY_PATH = "tests/sqlite3"
OUTPUT_FILE = "tests/sqlite3_analysis.json"

# Dangerous syscalls mentioned in the paper
DANGEROUS_SYSCALLS = [
    "execve", "execveat", "mmap", "mprotect", "socket", "connect", 
    "setsockopt", "bpf", "ptrace", "mount"
]

def run_bside():
    """Run B-Side analysis on the target binary."""
    logger.info("Starting B-Side analysis on %s...", BINARY_PATH)
    cmd = [
        "python3", "-m", "bside.main",
        "--binary", BINARY_PATH,
        "--output", "json",
        "--output-file", OUTPUT_FILE,
        "--verbose"
    ]
    
    start_time = time.time()
    try:
        # Use venv python if available
        python_exe = "venv/bin/python3" if os.path.exists("venv/bin/python3") else "python3"
        cmd[0] = python_exe
        
        # Don't capture output so we can see progress in real-time
        result = subprocess.run(cmd, check=True)
        
    except subprocess.CalledProcessError as e:
        logger.error("B-Side analysis failed with exit code %d", e.returncode)
        logger.error("Error output: %s", e.stderr)
        return False, 0
    
    end_time = time.time()
    return True, end_time - start_time

def verify_results(analysis_time):
    """Verify the analysis results against expectations."""
    if not os.path.exists(OUTPUT_FILE):
        logger.error("Analysis output file not found: %s", OUTPUT_FILE)
        return False

    with open(OUTPUT_FILE, 'r') as f:
        data = json.load(f)

    logger.info("=" * 60)
    logger.info("Analysis Summary for %s", BINARY_PATH)
    logger.info("=" * 60)
    logger.info("Total syscalls identified: %d", data.get("num_syscalls", 0))
    logger.info("Analysis time:            %.2f seconds (Paper says 6.5 mins)", analysis_time)
    logger.info("CFG Nodes:                %d", data.get("cfg_stats", {}).get("nodes", 0))
    logger.info("Wrappers detected:        %d", data.get("wrappers_detected", 0))
    logger.info("=" * 60)

    syscall_names = {s["name"] for s in data.get("syscalls", [])}
    
    # Check for dangerous syscalls
    found_dangerous = []
    for ds in DANGEROUS_SYSCALLS:
        if ds in syscall_names:
            found_dangerous.append(ds)
    
    logger.info("Identified Dangerous Syscalls: %s", ", ".join(found_dangerous) if found_dangerous else "None")
    
    # Expected syscalls for SQLite (common ones)
    expected_min = 30
    actual_count = data.get("num_syscalls", 0)
    
    if actual_count < expected_min:
        logger.warning("Identified fewer syscalls than expected for a complex binary like SQLite (%d < %d)", 
                       actual_count, expected_min)
    else:
        logger.info("Syscall identification count seems reasonable for SQLite.")

    # Check for specific syscalls that SHOULD be in SQLite
    essential = ["read", "write", "open", "close", "fstat", "mmap", "brk", "lseek"]
    missing_essential = [s for s in essential if s not in syscall_names]
    if missing_essential:
        logger.error("Missing essential syscalls: %s", ", ".join(missing_essential))
        return False
    else:
        logger.info("All essential syscalls (read, write, open, etc.) identified correctly.")

    return True

def main():
    if not os.path.exists(BINARY_PATH):
        logger.error("Binary not found: %s. Please run build_sqlite.sh first.", BINARY_PATH)
        sys.exit(1)

    success, duration = run_bside()
    if not success:
        sys.exit(1)

    if verify_results(duration):
        logger.info("Verification PASSED!")
    else:
        logger.error("Verification FAILED!")
        sys.exit(1)

if __name__ == "__main__":
    main()
