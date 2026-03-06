# XPLOG Attack Emulator Dataset

5 Go-based attack emulators designed to produce **distinct syscall patterns** for testing XPLOG's GNN-based lossy log recovery.

## Key Design Principle

Attacks are **realistically interleaved** with normal traffic — not isolated bursts:

```
Normal mode:   [N][N][N][N][N][N][N][N][N][N][N]...
Attack mode:   [N][N][N][A][N][N][N][N][A][N][N]...  (attack ops hidden among normal)
```

## Attacks

| # | Name | Port (normal/attack) | Anomalous Syscalls |
|---|------|---------------------|-------------------|
| 1 | SQL Injection → Cmd Exec | 8081 / 8091 | `clone→execve→open→read→write` |
| 2 | Reverse Shell | 9081 / 9091 | `socket→connect→dup2×3→execve` |
| 3 | Path Traversal | 8082 / 8092 | `open("/etc/passwd")→read→send` |
| 4 | Data Exfiltration | 8083 / 8093 | `open→read→socket→connect→send` (per-file) |
| 5 | Cryptominer Dropper | 8084 / 8094 | Multi-phase: `connect→recv→write→execve→unlinkat` |

## Quick Start

```bash
# Build all images
docker compose build

# Run normal-mode only (baseline logs)
docker compose --profile normal up

# Run attack-mode only (interleaved attack logs)
docker compose --profile attack up

# Or use the full pipeline script (runs normal → attack sequentially)
chmod +x run_all.sh
./run_all.sh 120s
```

## Configuration

Each emulator accepts these environment variables / flags:

| Variable | Flag | Default | Description |
|----------|------|---------|-------------|
| `MODE` | `--mode` | `normal` | `normal` or `attack` |
| `DURATION` | `--duration` | `120s` | Total runtime |
| — | `--attack-interval` | `5s` | Mean time between attack actions (Poisson) |
| — | `--normal-rate` | `10` | Normal operations per second |

## Label Files

Each attack-mode container produces `/app/labels.jsonl` with ground-truth timestamps:

```json
{"ts":1709712345678901234,"type":"sqli_exec","detail":"sh -c echo Searching for user: ; cat /etc/hostname"}
{"ts":1709712350123456789,"type":"path_traversal","detail":"requested=../../etc/passwd resolved=/etc/passwd"}
{"ts":1709712355678901234,"type":"data_exfil","detail":"file=/etc/hostname bytes=12"}
{"ts":1709712360123456789,"type":"dropper_c2_beacon","detail":"cycle=0","phase":1}
```

`run_all.sh` automatically copies these to `./collected_labels/`.

## Using with XPLOG

1. Start XPLOG collector: `docker compose -f ../docker-compose-collector.yml up -d`
2. Start XPLOG agent on host: `sudo ./xlp`
3. Run emulators: `./run_all.sh 120s`
4. Collector logs will contain both normal and attack syscall traces
5. Use `collected_labels/*.jsonl` to identify which log entries are attacks

## Directory Structure

```
dataset/
├── README.md
├── docker-compose.yml
├── run_all.sh
├── collected_labels/           (created by run_all.sh)
├── 01_sqli_cmd_exec/
├── 02_reverse_shell/
├── 03_path_traversal/
├── 04_data_exfiltration/
└── 05_cryptominer_dropper/
```
