import torch
import torch.nn.functional as F
from torch_geometric.data import Data
import pandas as pd
import numpy as np
from sklearn.metrics import recall_score, precision_score, f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from XPLOG_Collector.scripts.train_detector import SyscallGCN, prepare_graph_data

def evaluate_model(model, data, features_mask=None):
    model.eval()
    with torch.no_grad():
        x = data.x.clone()
        if features_mask is not None:
            # Mask features (set to 0)
            x = x * torch.tensor(features_mask, dtype=torch.float)
            
        out = model(x, data.edge_index)
        probs = F.softmax(out, dim=1)[:, 1].numpy()
        preds = out.argmax(dim=1).numpy()
        y = data.y.numpy()
        
        return {
            "precision": float(precision_score(y, preds, zero_division=0)),
            "recall": float(recall_score(y, preds, zero_division=0)),
            "f1": float(f1_score(y, preds, zero_division=0)),
            "auc": float(roc_auc_score(y, probs))
        }

def run_experiment():
    print("Loading Refined Data (One-Hot)...")
    df = pd.read_csv("datasets/full_features.csv")
    
    # Calculate pos_weight
    num_attacks = df['is_attack'].sum()
    num_normal = len(df) - num_attacks
    pos_weight = float(num_normal / num_attacks)
    print(f"Dataset Imbalance: {num_normal}:{num_attacks} (Weight: {pos_weight:.2f})")
    
    scaler = StandardScaler()
    df[['retval', 'seq_len']] = scaler.fit_transform(df[['retval', 'seq_len']])
    
    # Split
    train_df = df.sample(frac=0.8, random_state=42)
    test_df = df.drop(train_df.index)
    
    train_data = prepare_graph_data(train_df)
    test_data = prepare_graph_data(test_df)
    
    # Feature indices
    # baseline_mask starts with [1 (retval), 1 (seq_len), 0 (bside_violation), 1, 1, ... (sc_vars)]
    num_total_features = train_data.x.shape[1]
    baseline_mask = [1, 1, 0] + [1] * (num_total_features - 3)
    hybrid_mask = [1] * num_total_features

    # ---------------------------------------------------------
    # Experiment 1: Baseline (uProv - No B-Side)
    # ---------------------------------------------------------
    print("\n--- Training Refined Baseline (uProv + One-Hot) ---")
    model_baseline = SyscallGCN(num_node_features=num_total_features, num_classes=2)
    opt = torch.optim.Adam(model_baseline.parameters(), lr=0.01)
    
    for epoch in range(101):
        model_baseline.train()
        opt.zero_grad()
        x_masked = train_data.x * torch.tensor(baseline_mask, dtype=torch.float)
        out = model_baseline(x_masked, train_data.edge_index)
        loss = F.cross_entropy(out, train_data.y, weight=torch.tensor([1.0, pos_weight]))
        loss.backward()
        opt.step()
        if epoch % 25 == 0: print(f"Epoch {epoch}: Loss {loss.item():.4f}")
        
    metrics_baseline = evaluate_model(model_baseline, test_data, features_mask=baseline_mask)

    # ---------------------------------------------------------
    # Experiment 2: Hybrid (uProv + B-Side + One-Hot)
    # ---------------------------------------------------------
    print("\n--- Training Refined Hybrid (uProv + B-Side + One-Hot) ---")
    model_hybrid = SyscallGCN(num_node_features=num_total_features, num_classes=2)
    opt = torch.optim.Adam(model_hybrid.parameters(), lr=0.01)
    
    for epoch in range(101):
        model_hybrid.train()
        opt.zero_grad()
        out = model_hybrid(train_data.x, train_data.edge_index)
        loss = F.cross_entropy(out, train_data.y, weight=torch.tensor([1.0, pos_weight]))
        loss.backward()
        opt.step()
        if epoch % 25 == 0: print(f"Epoch {epoch}: Loss {loss.item():.4f}")
        
    metrics_hybrid = evaluate_model(model_hybrid, test_data)

    # ---------------------------------------------------------
    # Final Report
    # ---------------------------------------------------------
    results = {
        "Baseline (uProv + One-Hot)": metrics_baseline,
        "Hybrid (uProv + B-Side + One-Hot)": metrics_hybrid
    }
    
    res_df = pd.DataFrame(results).T
    print("\n============================================")
    print(" REFINED COMPARATIVE RESULTS ")
    print("============================================")
    print(res_df.to_string())
    print("============================================")
    
    res_df.to_csv("datasets/comparison_refined.csv")

if __name__ == "__main__":
    run_experiment()
