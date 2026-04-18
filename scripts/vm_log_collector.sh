#!/bin/bash
# scripts/vm_log_collector.sh
# Automates the collection of filtered XPLOG logs for ML training.
# Usage: ./scripts/vm_log_collector.sh [duration] [scenario]
# Example: ./scripts/vm_log_collector.sh 60s sqli

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="${PROJECT_ROOT}/bin"
COLLECTOR_LOG_DIR="${PROJECT_ROOT}/XPLOG_Collector/logs"
DURATION="${1:-60s}"
SCENARIO="${2:-all}"

mkdir -p "${COLLECTOR_LOG_DIR}"

echo "============================================"
echo " XPLOG Filtered Log Collector"
echo " Target: ${SCENARIO^} (Duration: ${DURATION})"
echo "============================================"

# Helper to stop containers
cleanup_docker() {
    echo "[Cleanup] Stopping containers..."
    cd "${PROJECT_ROOT}/dataset"
    if [ "$SCENARIO" == "all" ]; then
        docker compose --profile normal stop >/dev/null 2>&1 || true
        docker compose --profile attack stop >/dev/null 2>&1 || true
    else
        docker compose stop "${SCENARIO}_normal" "${SCENARIO}_attack" >/dev/null 2>&1 || true
    fi
}

# 1. Start Collector
echo "[1/4] Starting XPLOG Collector..."
cd "${PROJECT_ROOT}/XPLOG_Collector"
"${BIN_DIR}/server" > collector_session.log 2>&1 &
COLLECTOR_PID=$!
sleep 2

# 2. Start Agent with Container Filtering
echo "[2/4] Starting XPLOG Agent (Container Filtering)..."
"${BIN_DIR}/xlp" -c > agent_session.log 2>&1 &
AGENT_PID=$!
sleep 5

# 3. Run Emulators
echo "[3/4] Running Dataset Emulators..."
cd "${PROJECT_ROOT}/dataset"

if [ "$SCENARIO" == "all" ]; then
    ./run_all.sh "${DURATION}"
else
    # Run individual scenario
    echo "      Running Normal phase for ${SCENARIO}..."
    docker compose up -d "${SCENARIO}_normal"
    sleep $(echo "${DURATION}" | sed 's/s//')
    docker compose stop "${SCENARIO}_normal"
    
    echo "      Pausing 5s..."
    sleep 5
    
    echo "      Running Attack phase for ${SCENARIO}..."
    docker compose up -d "${SCENARIO}_attack"
    sleep $(echo "${DURATION}" | sed 's/s//')
    
    # Collect labels
    echo "      Collecting labels..."
    mkdir -p collected_labels
    docker cp "${SCENARIO}_attack:/app/labels.jsonl" "collected_labels/${SCENARIO}_attack_labels.jsonl" 2>/dev/null || true
    
    docker compose stop "${SCENARIO}_attack"
fi

# 4. Cleanup
echo "[4/4] Stopping Agent and Collector..."
sudo kill $AGENT_PID || true
kill $COLLECTOR_PID || true
cleanup_docker

echo ""
echo "============================================"
echo " Log Collection Complete!"
echo " Logs located in: ${COLLECTOR_LOG_DIR}"
echo "============================================"
echo ""
