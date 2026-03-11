"""
synthetic_pcap_generator.py

Generates a realistic synthetic PCAP file with 4 attack/activity scenarios
baked in. This gives you guaranteed detections when demoing the analyzer.

Usage: python synthetic_pcap_generator.py
Output: sample_traffic.pcap  (in the same directory)

Scenarios included:
  1. Normal browsing traffic (HTTP/HTTPS to common sites)
  2. Port scan attack (attacker sweeping 50 ports on a victim)
  3. SSH brute-force attempt (many connections to port 22)
  4. Data exfiltration simulation (large outbound transfer after scan)
"""

from scapy.all import (
    Ether, IP, TCP, UDP, Raw,
    wrpcap, RandShort
)
import random
import time

# ── IP Addresses used in scenarios ──────────────────────────────────────────
LOCAL_VICTIM   = "192.168.1.100"   # Your machine (victim)
LOCAL_USER     = "192.168.1.101"   # Normal user on network
ATTACKER_IP    = "45.33.32.156"    # External attacker (Shodan's IP — well known)
EXFIL_SERVER   = "185.220.101.45"  # Known Tor exit node IP
LEGIT_SERVER1  = "142.250.80.46"   # Google
LEGIT_SERVER2  = "104.244.42.65"   # Twitter/X

packets = []
BASE_TIME = time.time() - 300  # Start 5 minutes ago

def ts(offset_seconds):
    """Return a timestamp offset from base time."""
    return BASE_TIME + offset_seconds

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 1: Normal HTTP/HTTPS browsing traffic (T+0s to T+30s)
# ────────────────────────────────────────────────────────────────────────────
print("[*] Generating Scenario 1: Normal browsing traffic...")

for i in range(20):
    t = ts(i * 1.5)
    src_port = random.randint(49152, 65535)

    # SYN
    pkt = Ether() / IP(src=LOCAL_USER, dst=LEGIT_SERVER1, ttl=64) / \
          TCP(sport=src_port, dport=443, flags="S", seq=1000)
    pkt.time = t
    packets.append(pkt)

    # SYN-ACK
    pkt = Ether() / IP(src=LEGIT_SERVER1, dst=LOCAL_USER, ttl=54) / \
          TCP(sport=443, dport=src_port, flags="SA", seq=2000, ack=1001)
    pkt.time = t + 0.02
    packets.append(pkt)

    # ACK + Data
    payload = b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"
    pkt = Ether() / IP(src=LOCAL_USER, dst=LEGIT_SERVER1, ttl=64) / \
          TCP(sport=src_port, dport=443, flags="PA", seq=1001, ack=2001) / \
          Raw(load=payload)
    pkt.time = t + 0.03
    packets.append(pkt)

    # Response with some data
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n" + b"A" * 512
    pkt = Ether() / IP(src=LEGIT_SERVER1, dst=LOCAL_USER, ttl=54) / \
          TCP(sport=443, dport=src_port, flags="PA", seq=2001, ack=1039) / \
          Raw(load=response)
    pkt.time = t + 0.08
    packets.append(pkt)

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 2: Port Scan (T+60s to T+90s)
# Attacker sweeps 50 ports on victim — SYN scan (half-open)
# ────────────────────────────────────────────────────────────────────────────
print("[*] Generating Scenario 2: Port scan attack...")

scanned_ports = random.sample(range(1, 1024), 50)
for i, port in enumerate(scanned_ports):
    t = ts(60 + i * 0.4)  # One probe every 0.4 seconds

    # SYN probe from attacker
    pkt = Ether() / IP(src=ATTACKER_IP, dst=LOCAL_VICTIM, ttl=45) / \
          TCP(sport=random.randint(40000, 60000), dport=port, flags="S", seq=random.randint(1000, 9999))
    pkt.time = t
    packets.append(pkt)

    # RST/ACK back from victim (port closed) — except a few "open" ports
    if port in [22, 80, 443, 3389]:
        # Port open — SYN-ACK
        pkt = Ether() / IP(src=LOCAL_VICTIM, dst=ATTACKER_IP, ttl=128) / \
              TCP(sport=port, dport=pkt[TCP].sport, flags="SA", seq=5000, ack=pkt[TCP].seq + 1)
        pkt.time = t + 0.005
        packets.append(pkt)
    else:
        # Port closed — RST
        pkt = Ether() / IP(src=LOCAL_VICTIM, dst=ATTACKER_IP, ttl=128) / \
              TCP(sport=port, dport=pkt[TCP].sport, flags="R", seq=0)
        pkt.time = t + 0.005
        packets.append(pkt)

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 3: SSH Brute-force (T+100s to T+160s)
# Attacker hammers port 22 with repeated connection attempts
# ────────────────────────────────────────────────────────────────────────────
print("[*] Generating Scenario 3: SSH brute-force on port 22...")

for i in range(25):
    t = ts(100 + i * 2.5)
    src_port = random.randint(40000, 60000)

    # SYN
    pkt = Ether() / IP(src=ATTACKER_IP, dst=LOCAL_VICTIM, ttl=45) / \
          TCP(sport=src_port, dport=22, flags="S", seq=random.randint(10000, 99999))
    pkt.time = t
    packets.append(pkt)

    # SYN-ACK (port 22 is open from scenario 2)
    pkt = Ether() / IP(src=LOCAL_VICTIM, dst=ATTACKER_IP, ttl=128) / \
          TCP(sport=22, dport=src_port, flags="SA", seq=50000, ack=pkt[TCP].seq + 1)
    pkt.time = t + 0.01
    packets.append(pkt)

    # SSH banner exchange
    ssh_banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    pkt = Ether() / IP(src=LOCAL_VICTIM, dst=ATTACKER_IP, ttl=128) / \
          TCP(sport=22, dport=src_port, flags="PA") / \
          Raw(load=ssh_banner)
    pkt.time = t + 0.05
    packets.append(pkt)

    # Auth attempt (simulated)
    auth_data = b"\x00\x00\x01\x00" + b"\x15" * 60  # Fake SSH auth packet
    pkt = Ether() / IP(src=ATTACKER_IP, dst=LOCAL_VICTIM, ttl=45) / \
          TCP(sport=src_port, dport=22, flags="PA") / \
          Raw(load=auth_data)
    pkt.time = t + 0.1
    packets.append(pkt)

    # RST — connection reset (failed auth)
    pkt = Ether() / IP(src=LOCAL_VICTIM, dst=ATTACKER_IP, ttl=128) / \
          TCP(sport=22, dport=src_port, flags="R")
    pkt.time = t + 0.15
    packets.append(pkt)

# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 4: Data Exfiltration (T+200s to T+250s)
# After successful access, attacker sends large amount of data outbound
# ────────────────────────────────────────────────────────────────────────────
print("[*] Generating Scenario 4: Data exfiltration simulation...")

exfil_port = random.randint(40000, 60000)
seq = 10000

# Initial connection to exfil server
pkt = Ether() / IP(src=LOCAL_VICTIM, dst=EXFIL_SERVER, ttl=64) / \
      TCP(sport=exfil_port, dport=443, flags="S", seq=seq)
pkt.time = ts(200)
packets.append(pkt)

pkt = Ether() / IP(src=EXFIL_SERVER, dst=LOCAL_VICTIM, ttl=50) / \
      TCP(sport=443, dport=exfil_port, flags="SA", seq=20000, ack=seq + 1)
pkt.time = ts(200.05)
packets.append(pkt)

# Large outbound data chunks (simulating file transfer)
for i in range(30):
    t = ts(200 + 1 + i * 1.5)
    chunk = b"EXFIL_DATA_CHUNK_" + str(i).encode() + b"_" + b"X" * 1400
    pkt = Ether() / IP(src=LOCAL_VICTIM, dst=EXFIL_SERVER, ttl=64) / \
          TCP(sport=exfil_port, dport=443, flags="PA", seq=seq + i * 1418) / \
          Raw(load=chunk)
    pkt.time = t
    packets.append(pkt)

    # ACK from server
    pkt = Ether() / IP(src=EXFIL_SERVER, dst=LOCAL_VICTIM, ttl=50) / \
          TCP(sport=443, dport=exfil_port, flags="A", seq=20001, ack=seq + (i + 1) * 1418)
    pkt.time = t + 0.02
    packets.append(pkt)

# ────────────────────────────────────────────────────────────────────────────
# Sort all packets by timestamp and write to PCAP
# ────────────────────────────────────────────────────────────────────────────
print("[*] Sorting packets by timestamp...")
packets.sort(key=lambda p: float(p.time))

output_file = "sample_traffic.pcap"
wrpcap(output_file, packets)

print(f"\n{'='*50}")
print(f"  SUCCESS! Generated {len(packets)} packets")
print(f"  Output: {output_file}")
print(f"\n  Scenarios included:")
print(f"    [T+000s] Normal HTTPS browsing (20 flows)")
print(f"    [T+060s] Port scan — {ATTACKER_IP} → {LOCAL_VICTIM} (50 ports)")
print(f"    [T+100s] SSH brute-force — 25 login attempts on port 22")
print(f"    [T+200s] Data exfiltration — 30 chunks to {EXFIL_SERVER}")
print(f"\n  Next step: python app.py  (then upload this PCAP)")
print(f"{'='*50}")
