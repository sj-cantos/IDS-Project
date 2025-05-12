import sys
import ctypes
import os
import subprocess
import threading
import time
from datetime import datetime
import pyshark
import pandas as pd
import numpy as np
import xgboost as xgb
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import os
import pandas as pd
 # Import your existing function
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cols import column_rename_map
from ids import class_id_to_label
import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FEATURES_PATH = r"D:\IDS-Project\training_features.json"
# Configuration
TEST_CSV = r"D:\IDS-Project\test_assets\ten_malicious_rows.csv"  
OUTPUT_CSV = r"D:\IDS-Project\test_assets\test_output.csv"  
def predict_anomalies(csv_path, model_path=r"D:\IDS-Project\xgb_ids_model_balanced (2).json"):
    try:
        print(f"[+] Loading data from: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Apply column renaming first
        df = df.rename(columns=column_rename_map)
        df_original = df.copy()

        # Preprocessing steps - only drop columns that exist
        non_numeric_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label', 'Source Port', 'Destination Port']
        df = df.drop(columns=[col for col in non_numeric_cols if col in df.columns], errors='ignore')

        # Drop columns by index only if the indices exist in df
        columns_to_drop = [0, 14, 15, 36, 67]
        existing_indices = [i for i in columns_to_drop if i < df.shape[1]]
        df = df.drop(df.columns[existing_indices], axis=1)
        # Clean and normalize features
        df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
        if 'Flow Duration' in df.columns:
            df['Flow Duration'] = df['Flow Duration'].replace(0, 1) / 1e6  # Convert to seconds
            
        # Add SYN flood detection features
        if all(col in df.columns for col in ['SYN Flag Count', 'Total Fwd Packets']):
            df['syn_ratio'] = df['SYN Flag Count'] / (df['Total Fwd Packets'] + 1e-5)
            df['short_flow'] = (df['Flow Duration'] < 0.1).astype(int)  # Flows < 100ms
        
        # Align features with model expectations
        with open(FEATURES_PATH) as f:
            expected_features = json.load(f)

        for feature in expected_features:
            if feature not in df.columns:
                df[feature] = 0
        df = df[expected_features]

        # Load model and predict
        print("[+] Loading XGBoost model...")
        model = xgb.Booster()
        model.load_model(model_path)
        dmatrix = xgb.DMatrix(df)
        
        # Get prediction probabilities
        pred_probs = model.predict(dmatrix)
        predicted_classes = []
        confidence_scores = []
        
        for i, probs in enumerate(pred_probs):
            max_prob = max(probs)
            pred_class = np.argmax(probs)
            confidence_scores.append(max_prob)
            
            # Special handling for SYN flood patterns
            if ('syn_ratio' in df.columns and df.iloc[i]['syn_ratio'] > 0.7 and 
                df.iloc[i]['short_flow'] == 1 and 
                max_prob < 0.9):  # Lower threshold for SYN floods
                predicted_classes.append("DoS_SYN_Flood")
            else:
                predicted_classes.append(class_id_to_label.get(pred_class, "UNKNOWN"))

        # Add predictions to the original dataframe
        df_original['prediction'] = predicted_classes
        df_original['confidence'] = confidence_scores
        
        # Now we can apply suspicious criteria
        suspicious_criteria = (
            (df_original['SYN Flag Count'] > 100) if 'SYN Flag Count' in df_original.columns else False |
            (df_original['Flow Duration'] < 0.01) if 'Flow Duration' in df_original.columns else False |
            (df_original['Total Fwd Packets'] > 500) if 'Total Fwd Packets' in df_original.columns else False
        )
        
        # Only mark as suspicious if not already detected as an attack
        df_original.loc[suspicious_criteria & (df_original['prediction'] == 'BENIGN'), 'prediction'] = 'SUSPICIOUS'
        
        # Debug output - use only available columns
        print("\n[+] Detection Summary:")
        print(df_original['prediction'].value_counts())
        
        # Highlight suspicious flows - check which columns exist first
        available_columns = [col for col in ['flow_id', 'src_ip', 'dst_ip', 'prediction', 'confidence'] 
                           if col in df_original.columns]
        
        suspicious = df_original[df_original['prediction'].str.contains('DoS|SUSPICIOUS')]
        if not suspicious.empty:
            print("\n[!] Suspicious flows detected:")
            print(suspicious[available_columns].to_string())
        
        return df_original

    except Exception as e:
        print(f"[!] Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return None
def analyze_csv(csv_path):
    """Reuse your existing predict_anomalies function"""
    print(f"\n[+] Analyzing {csv_path}")
    
    # Call your existing function
    results = predict_anomalies(csv_path)
    
    if results is not None:
        # Save full results
        results.to_csv(OUTPUT_CSV, index=False)
        print(f"[+] Saved results to {OUTPUT_CSV}")
        
        # Print detection summary
        print("\n=== Detection Summary ===")
        print(results['prediction'].value_counts())
        
        # Show alerts
        # alerts = results[results['prediction'] != 'BENIGN']
        # if not alerts.empty:
        #     print("\n[!] ALERTS FOUND:")
        #     print(alerts[['src_ip', 'dst_ip', 'prediction', 'confidence']].to_string(index=False))
        # else:
        #     print("\n[+] No threats detected")

if __name__ == "__main__":
    analyze_csv(TEST_CSV)