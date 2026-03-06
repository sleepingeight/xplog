#!/bin/bash
set -e

DURATION="${1:-120s}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LABELS_DIR="${SCRIPT_DIR}/collected_labels"

echo "============================================"
echo " XPLOG Attack Emulator Dataset Runner"
echo " Duration per phase: ${DURATION}"
echo "============================================"

cd "${SCRIPT_DIR}"

# Build all images.
echo ""
echo "[1/5] Building all Docker images..."
docker compose build

# Create labels output directory.
mkdir -p "${LABELS_DIR}"

# Phase 1: Run NORMAL mode.
echo ""
echo "[2/5] Running NORMAL mode containers (${DURATION})..."
echo "      Start XPLOG agent/collector now if not already running."
echo ""

DURATION="${DURATION}" docker compose --profile normal up -d
echo "      Waiting for normal-mode to run..."
sleep $(echo "${DURATION}" | sed 's/s//')

echo "      Stopping normal-mode containers..."
# Containers will self-terminate after duration, but stop any lingering ones.
docker compose --profile normal stop 2>/dev/null || true
docker compose --profile normal rm -f 2>/dev/null || true

echo ""
echo "[3/5] Pausing 5 seconds between phases..."
sleep 5

# Phase 2: Run ATTACK mode.
echo ""
echo "[4/5] Running ATTACK mode containers (${DURATION})..."
echo ""

DURATION="${DURATION}" docker compose --profile attack up -d
echo "      Waiting for attack-mode to run..."
sleep $(echo "${DURATION}" | sed 's/s//')

# Collect label files before stopping.
echo ""
echo "[5/5] Collecting label files..."
CONTAINERS=("sqli_attack" "revshell_attack" "pathtraversal_attack" "exfil_attack" "dropper_attack")
for container in "${CONTAINERS[@]}"; do
    echo "      Copying labels from ${container}..."
    docker cp "${container}:/app/labels.jsonl" "${LABELS_DIR}/${container}_labels.jsonl" 2>/dev/null || echo "      Warning: no labels from ${container}"
done

docker compose --profile attack stop 2>/dev/null || true
docker compose --profile attack rm -f 2>/dev/null || true

echo ""
echo "============================================"
echo " DONE!"
echo " Labels saved to: ${LABELS_DIR}/"
echo "============================================"
echo ""
echo "Label files:"
ls -la "${LABELS_DIR}/" 2>/dev/null || echo "  (none found)"
echo ""
echo "Next steps:"
echo "  1. Compare XPLOG collector logs between normal and attack phases"
echo "  2. Use label files to identify which syscalls were attack-related"
echo "  3. Feed into GNN for training/testing"
