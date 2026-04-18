#!/bin/bash
# scripts/generate_training_data.sh
# Automates the 60s collection batch for all emulators.

SCENARIOS=("sqli" "revshell" "pathtraversal" "exfil" "dropper")
DURATION="60s"

echo "============================================"
echo " XPLOG Training Data Generator "
echo "============================================"

for sc in "${SCENARIOS[@]}"; do
    echo "[*] Collecting data for: $sc (Duration: $DURATION)"
    sudo ./scripts/vm_log_collector.sh $DURATION $sc
    
    # Store with a distinct name to avoid overwrite
    mkdir -p dataset/training_logs
    latest_log=$(ls -t XPLOG_Collector/logs/*.txt | head -n 1)
    cp "$latest_log" "dataset/training_logs/${sc}_60s.txt"
    
    echo "[+] Saved to dataset/training_logs/${sc}_60s.txt"
    echo "--------------------------------------------"
done

echo "Batch Collection Complete!"
