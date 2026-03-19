
import sys
import os
import pandas as pd
import numpy as np
from datetime import datetime

# Add the project root to sys.path
sys.path.append(os.getcwd())

from log_analyzer.models import PCA, IsolationForest
from log_analyzer import preprocessing

# Path to the forensic data
log_file = r'data/HDFS/forensic_training_data.csv'

def run_anomaly_detection():
    print(f"Loading log file: {log_file}")
    df = pd.read_csv(log_file)
    
    # Create a unified 'Event' column combining EventID and Level
    df['Event'] = df['EventID'].astype(str) + "-" + df['Level'].astype(str)
    
    # Preprocessing: Convert TimeGenerated to datetime and create 1-minute time buckets
    df['TimeGenerated'] = pd.to_datetime(df['TimeGenerated'], dayfirst=True)
    df['TimeBucket'] = df['TimeGenerated'].dt.floor('1min')
    
    print("Grouping logs into 1-minute sessions per computer...")
    grouped = df.groupby(['Computer', 'TimeBucket'])
    
    session_info = []
    X_seq = []
    
    for (computer, bucket), group in grouped:
        event_list = group['Event'].tolist()
        X_seq.append(event_list)
        session_info.append({
            'Computer': computer,
            'Time': bucket,
            'Events': len(event_list),
            'EventList': event_list,
            'Messages': group['Message'].tolist()
        })
    
    X_seq = np.array(X_seq, dtype=object)
    
    # Feature extraction
    print("Extracting features using TF-IDF...")
    feature_extractor = preprocessing.FeatureExtractor()
    x_train = feature_extractor.fit_transform(X_seq, term_weighting='tf-idf', normalization='zero-mean')
    
    # Model 1: PCA
    print("Running PCA Anomaly Detection...")
    pca_model = PCA()
    pca_model.fit(x_train)
    y_pred_pca = pca_model.predict(x_train) # 1 for anomaly, 0 for normal
    
    # Model 2: Isolation Forest
    print("\nRunning Isolation Forest Anomaly Detection (contamination=0.05)...")
    if_model = IsolationForest(contamination=0.05, random_state=42)
    if_model.fit(x_train)
    y_pred_if = if_model.predict(x_train) # 1 for anomaly, 0 for normal in log_analyzer
    
    # Combine findings (sessions flagged by either model)
    combined_anomalies = np.where((y_pred_pca == 1) | (y_pred_if == 1))[0]
    
    print(f"\nPCA detected {int(sum(y_pred_pca))} anomalies.")
    print(f"Isolation Forest detected {int(sum(y_pred_if))} anomalies.")
    print(f"Total unique anomalous sessions detected: {len(combined_anomalies)}")

    # Reporting
    if len(combined_anomalies) > 0:
        print("\nSUMMARY OF TOP ANOMALIES DETECTED")
        print("=" * 110)
        # Sort anomalies: prioritize sessions with 'Critical' or 'Error'
        sorted_anomalies = sorted(combined_anomalies, key=lambda i: (
            'Critical' in [e.split('-')[1] for e in session_info[i]['EventList']],
            'Error' in [e.split('-')[1] for e in session_info[i]['EventList']],
            'Warning' in [e.split('-')[1] for e in session_info[i]['EventList']],
            session_info[i]['Events']
        ), reverse=True)

        for idx in sorted_anomalies[:15]: 
            info = session_info[idx]
            severities = [e.split('-')[1] for e in info['EventList']]
            
            if 'Critical' in severities: status = "!!! CRITICAL !!!"
            elif 'Error' in severities: status = "!! ERROR !!"
            elif 'Warning' in severities: status = "! WARNING !"
            else: status = "UNUSUAL BEHAVIOR"
            
            print(f"[{status:^16}] Time: {info['Time']} | Computer: {info['Computer']} | Event Count: {info['Events']}")
            unique_events = sorted(list(set(info['EventList'])))
            print(f"   Event Types: {', '.join(unique_events)}")
            
            # Find the most relevant message to display
            best_msg = info['Messages'][0]
            for m in info['Messages']:
                if any(word in m for word in ["Network", "failed", "Access", "Critical", "Destination", "Bytes"]):
                    best_msg = m
                    break
            print(f"   Key Detail: {best_msg[:160]}...")
            print("-" * 110)
    else:
        print("No anomalies detected by either model.")

if __name__ == '__main__':
    run_anomaly_detection()
