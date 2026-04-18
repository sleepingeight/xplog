import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import StandardScaler

class SyscallGCN(torch.nn.Module):
    def __init__(self, num_node_features, num_classes):
        super(SyscallGCN, self).__init__()
        self.conv1 = GCNConv(num_node_features, 64)
        self.conv2 = GCNConv(64, 32)
        self.classifier = torch.nn.Linear(32, num_classes)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.2, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        return self.classifier(x)

def prepare_graph_data(df, feature_cols=None):
    # Dynamic feature selection (Support for uProv graph features)
    if feature_cols is None:
        feature_cols = ['retval', 'seq_len', 'bside_violation'] + \
                      [c for c in df.columns if (c.startswith('sc_') or c.startswith('graph_'))]
    
    x = torch.tensor(df[feature_cols].values, dtype=torch.float)
    y = torch.tensor(df['is_attack'].values, dtype=torch.long)
    
    # Edges: Causal process sequencing
    edge_index = []
    df_sorted = df.sort_values(['host_pid', 'ts']).reset_index(drop=True)
    pids = df_sorted['host_pid'].values
    for i in range(len(pids) - 1):
        if pids[i] == pids[i+1]:
            edge_index.append([i, i+1])
            edge_index.append([i+1, i])
            
    edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    return Data(x=x, edge_index=edge_index, y=y)

def train(dataset_path="datasets/full_features_v3_graph.csv"):
    if not os.path.exists(dataset_path):
        print(f"Data missing at {dataset_path}.")
        return

    df = pd.read_csv(dataset_path)
    
    # Standardize numeric columns (including new graph features)
    numeric_cols = ['retval', 'seq_len', 'graph_nodes', 'graph_edges', 'graph_density']
    numeric_cols = [c for c in numeric_cols if c in df.columns]
    
    scaler = StandardScaler()
    df[numeric_cols] = scaler.fit_transform(df[numeric_cols])
    
    data = prepare_graph_data(df)
    
    num_attacks = df['is_attack'].sum()
    num_normal = len(df) - num_attacks
    pos_weight = torch.tensor([num_normal / num_attacks], dtype=torch.float)

    model = SyscallGCN(num_node_features=data.x.shape[1], num_classes=2)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    
    for epoch in range(101):
        model.train()
        optimizer.zero_grad()
        out = model(data.x, data.edge_index)
        loss = F.cross_entropy(out, data.y, weight=torch.tensor([1.0, pos_weight.item()]))
        loss.backward()
        optimizer.step()
        
        if epoch % 10 == 0:
            print(f'Epoch {epoch}: Loss {loss.item():.4f}')

    os.makedirs("models", exist_ok=True)
    torch.save(model.state_dict(), "models/gnn_detector_v3.pt")
    print("Training complete (v3 with Graph Features).")

if __name__ == "__main__":
    import os
    os.makedirs("models", exist_ok=True)
