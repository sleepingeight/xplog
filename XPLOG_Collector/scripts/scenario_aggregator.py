import pandas as pd
import numpy as np

class ScenarioAggregator:
    def __init__(self, window_seconds=5, alert_threshold=0.2):
        self.window_ns = window_seconds * 1_000_000_000
        self.alert_threshold = alert_threshold

    def aggregate_detections(self, df):
        """
        Processes a dataframe of syscall predictions and identifies attack windows.
        Expected columns: ['ts', 'is_attack', 'pred', 'bside_violation']
        """
        if df.empty: return []

        df = df.sort_values('ts').copy()
        start_ts = df['ts'].min()
        end_ts = df['ts'].max()
        
        alerts = []
        
        # Sliding window step: 1 second
        for current_start in range(start_ts, end_ts, 1_000_000_000):
            current_end = current_start + self.window_ns
            window_df = df[(df['ts'] >= current_start) & (df['ts'] < current_end)]
            
            if window_df.empty: continue
            
            # Hybrid Logic: An alert is counted if:
            # 1. GNN flags it (pred=1)
            # 2. OR B-Side flags it (bside_violation=1)
            # This ensures we don't miss attacks that only one system catches.
            anomalous_events = window_df[(window_df['pred'] == 1) | (window_df['bside_violation'] == 1)]
            
            anomaly_density = len(anomalous_events) / len(window_df)
            
            if anomaly_density > self.alert_threshold:
                alerts.append({
                    'ts_start': current_start,
                    'density': anomaly_density,
                    'is_true_attack': window_df['is_attack'].any()
                })
        
        return alerts

def evaluate_scenario_fidelity(df, aggregator):
    scenarios = df['scenario'].unique()
    sessions = []
    
    for sc in scenarios:
        for mode in [0, 1]: # Normal runs (0) vs Attack runs (1)
            mask = (df['scenario'] == sc) & (df['is_attack_session'] == mode)
            session_df = df[mask]
            
            if session_df.empty: continue
            
            alerts = aggregator.aggregate_detections(session_df)
            alert_triggered = len(alerts) > 0
            
            sessions.append({
                'Scenario': sc,
                'Type': 'Attack' if mode == 1 else 'Normal',
                'Alert_Triggered': alert_triggered,
                'Max_Density': max([a['density'] for a in alerts]) if alerts else 0
            })
            
    return pd.DataFrame(sessions)

if __name__ == "__main__":
    print("Scenario Aggregator v1 (Static-Filter Hybrid) Ready.")
