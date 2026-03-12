<div align="center">

```
███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    ██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
    ██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
    ██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
    ██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
    ███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
    ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
```

### 🛡️ Professional Network Traffic Analysis & SOC Analyst Training Platform
<img width="1830" height="741" alt="image" src="https://github.com/user-attachments/assets/f070e19c-6cc0-4b8a-93fb-0e8272c64d41" />

<br>

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-009639?style=for-the-badge&logo=wireshark&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-F38BA8?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-CBA6F7?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-FF6B6B?style=for-the-badge)

<br>

> *"Built for real threat hunters. Not just packet viewers — attack pattern recognizers."*

<br>

[🚀 Quick Start](#-quick-start) • [✨ Features](#-features) • [🔬 Investigation Lab](#-investigation-lab) • [🎯 Attack Detection](#-attack-detection) • [📸 Screenshots](#-screenshots) • [🗺️ Roadmap](#-roadmap)

</div>

---

## 🌟 What Is This?

A **full-stack network security analysis platform** built with Python + Flask + Scapy. It has two modes:

| Mode | Purpose |
|------|---------|
| 🔍 **Traffic Analyzer** | Upload real PCAPs, get Wireshark-level packet breakdown with geo-flagging, port scan detection, and correlation |
| 🧪 **Investigation Lab** | SOC analyst training platform — 20 pre-built attack scenarios with interactive learning, quizzes, and detection practice |

Built to bridge the gap between **reading about attacks** and **actually recognizing them in packet data**.

---

## ✨ Features

### 🔍 Traffic Analyzer (`localhost:5000`)

```
📁 Upload Support
├── .pcap / .pcapng / .cap     → Full Wireshark-level parsing
├── .csv                       → Wireshark/Zeek/Suricata exports
├── .xlsx / .xls               → Excel-format network logs  
└── .log / .txt                → Generic log files with auto IP extraction
```

```
📊 Analysis Modules
├── 🌍 Geo-Flagging            → External IP detection & country mapping
├── 🔌 Port Scan Detection     → SYN scan, NULL, FIN, XMAS, UDP, brute force
├── 🔗 Traffic Correlation     → Flow analysis, connection patterns
└── 📈 Traffic Statistics      → Protocol breakdown, top talkers, timeline
```

### 🧪 Investigation Lab (`localhost:5000/lab`)

```
🎓 Learning Platform
├── 📦 Packet Explorer         → Color-coded L2→L7 deep dive
│   ├── Filter by IP, Protocol, Flag, Port, Text
│   ├── 150 packets/page with full pagination
│   └── Complete hex dump + decoded fields
│
├── 🚨 Attack Detector         → 9 real-time detectors  
│   ├── Severity-sorted findings (CRITICAL → LOW)
│   ├── IOC details per finding
│   └── Packet-level evidence linking
│
├── 📚 Learn Mode              → Per-attack knowledge base
│   ├── How it works (protocol level)
│   ├── What to look for in packets
│   ├── Real-world context
│   └── MITRE ATT&CK mapping
│
└── 🧪 Quiz Mode               → 10 questions per attack type
    ├── Scenario-based questions
    ├── Immediate feedback
    └── Score tracking
```

---

## 🎯 Attack Detection

> All detectors use **behavioral analysis** — not just signatures. Designed to minimize false positives on real-world captures.

| # | Attack | Layer | MITRE | Detection Logic |
|---|--------|-------|-------|-----------------|
| 🔴 | **SYN Flood** | Transport | T1498.001 | High SYN rate + <20% completion ratio in 60s window |
| 🔴 | **TCP Session Hijacking** | Transport | T1557 | Sequence number jumps >50k + ACK storm ratio >70% |
| 🟠 | **RST Injection** | Transport | T1499 | RST source ≠ original session server + count >10 |
| 🟠 | **UDP Flood** | Transport | T1498 | >200 UDP packets from single src, >100/min peak |
| 🔴 | **DNS Tunneling** | Application | T1071.004 | Subdomain entropy >3.5 + label length >30 chars |
| 🟠 | **ARP Spoofing** | Data Link | T1557.002 | Single IP mapping to multiple MAC addresses |
| 🟠 | **Slowloris** | Application | T1499.001 | >200 SYNs to port 80/443 + >70% time coverage + sustained >120s |
| 🟡 | **IP Spoofing** | Network | T1599 | Private src → external dst with TTL < 20 |
| 🟡 | **ICMP Tunneling** | Network | T1095 | ICMP payload >64 bytes + high entropy |

<details>
<summary><b>💡 Why These Detectors Don't False-Positive on Normal Traffic</b></summary>

<br>

**Slowloris** — Threshold is 200+ connections AND 70%+ time coverage AND 120s duration. A browser opens 6-30 parallel connections in bursts then stops. Slowloris trickles connections steadily for minutes. These are fundamentally different patterns.

**IP Spoofing** — Only fires when TTL < 20. Normal outbound traffic (private→public) from your workstation has TTL=64 or 128. TTL < 20 means the packet barely traveled — suggesting it was crafted with a low TTL, a real spoofing indicator.

**TCP Hijacking** — Requires BOTH sequence number anomalies AND ACK storms. Normal HTTPS traffic has high ACK ratios but clean, continuous sequence numbers. Hijacking creates large sequence jumps (>50,000) that legitimate TCP doesn't produce.

</details>

---

## 🔬 Investigation Lab — 20 Attack PCAPs

Pre-generated synthetic attack captures for training:

<table>
<tr>
<td>

**🌊 Flooding Attacks**
- `01` SYN Flood
- `04` UDP Flood
- `18` Slowloris

</td>
<td>

**🔀 TCP Manipulation**
- `02` RST Injection  
- `03` TCP Session Hijack
- `05` Port Scan Suite

</td>
<td>

**🌐 DNS Attacks**
- `06` DNS Tunneling
- `07` DNS Amplification
- `08` Fast Flux DNS
- `09` DGA Domains

</td>
<td>

**🕵️ Evasion & Covert**
- `10` IP Spoofing
- `11` ICMP Tunneling
- `12` IP Fragmentation
- `19` SSL Stripping

</td>
</tr>
<tr>
<td>

**📡 Layer 2 Attacks**
- `13` ARP Spoofing
- `14` MAC Flooding

</td>
<td>

**💻 Application Layer**
- `15` HTTP Attacks
- `20` BGP Hijacking

</td>
<td>

**📤 Exfiltration**
- `16` SMTP Exfil
- `17` FTP Exfil

</td>
<td>

**🔥 Mega Combined**
- `00` All 20 attacks in one PCAP

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.8+
Wireshark (for Npcap driver on Windows)
```

### Installation

```bash
# Clone the repository
git clone https://github.com/Darkydeliver/Network_log_Analyzer.git
cd network-log-analyzer

# Install dependencies
pip install -r requirements.txt

# Verify setup
python setup_check.py
```

### Run

```bash
python app.py
```

Then open your browser:
- **Analyzer**: http://localhost:5000
- **Investigation Lab**: http://localhost:5000/lab

### Generate Sample Attack PCAPs

```bash
# Generate all 20 attack scenarios
python synthetic_pcap_generator.py

# PCAPs appear in static/lab_pcaps/
```

---

## 📁 Project Structure

```
network-log-analyzer/
│
├── 🚀 app.py                          # Flask application entry point
├── 🧪 lab_routes.py                   # Investigation Lab blueprint & API
├── ⚙️  setup_check.py                  # Dependency verification
├── 🎭 synthetic_pcap_generator.py     # Attack PCAP generation
├── 📋 requirements.txt
│
├── analyzer/                          # Core analysis engine
│   ├── 🔍 pcap_parser.py             # IPv4/IPv6/ARP packet parser
│   ├── 📊 traffic_stats.py           # Protocol & flow statistics  
│   ├── 🔌 port_scan.py               # 6-type port scan detector
│   ├── 🌍 geo_flag.py                # External IP geolocation
│   ├── 🔗 correlator.py              # Traffic correlation engine
│   ├── 🚨 attack_detector.py         # 9 behavioral attack detectors
│   └── 🎭 lab_pcap_generator.py      # Synthetic attack generator
│
├── templates/
│   ├── 🖥️  index.html                 # Main analyzer UI
│   └── 🧪 lab.html                   # Investigation Lab UI
│
└── static/
    └── lab_pcaps/                     # 20 pre-built attack scenarios
        ├── 00_mega_combined.pcap
        ├── 01_syn_flood.pcap
        └── ... (20 scenarios)
```

---

## 🌐 API Reference

<details>
<summary><b>Investigation Lab API Endpoints</b></summary>

```
POST /lab/upload
    Upload PCAP/CSV/XLSX/LOG file
    Returns: { job_id, status }

GET  /lab/status/<job_id>
    Poll analysis progress
    Returns: { progress, stage, complete }

GET  /lab/api/packets/<job_id>
    Paginated packet list (150/page)
    Params: page, filter_ip, filter_proto, filter_flag, filter_port, filter_text
    Returns: { packets[], total, pages }

GET  /lab/api/packet/<job_id>/<n>
    Full packet detail (L2→L7 + hex dump)
    Returns: complete packet dict

GET  /lab/api/attacks/<job_id>
    All detected attacks with knowledge + quiz
    Returns: { findings[], knowledge{} }

GET  /lab/api/ip/<job_id>/<ip>
    IP profile (connections, ports, timing)
    Returns: IP intelligence dict

GET  /lab/api/quiz/<attack_type>
    10 questions for attack type
    Attack types: SYN_FLOOD, DNS_TUNNELING, ARP_SPOOFING, etc.

POST /lab/api/quiz/check
    Validate quiz answer
    Body: { attack_type, question_index, answer_index }

GET  /lab/api/samples
    List available sample PCAPs
```

</details>

---

## 🛠️ Supported File Formats

| Format | Source | What's Extracted |
|--------|--------|-----------------|
| `.pcap` / `.pcapng` | Wireshark, tcpdump | Full L2-L7 headers, payload, hex dump |
| `.cap` | Various capture tools | Same as pcap |
| `.csv` | Wireshark export, Zeek, Suricata | Auto-detects column layout |
| `.xlsx` / `.xls` | Excel network logs | Flexible field mapping |
| `.log` / `.txt` | Generic logs | Regex IP/port extraction |

> 💡 **Best results**: Save as `.pcap` from Wireshark (`File → Save As → Wireshark/tcpdump format`)  
> CSV exports from Wireshark only contain 7 columns — deep protocol fields are lost.

---

## 🧠 Built For Learning

This tool was built alongside a structured **threat hunting curriculum** covering:

```
✅ Layer 2 (Internet Layer)  — IP headers, TTL analysis, ICMP abuse, fragmentation attacks
✅ Layer 3 (Transport Layer) — TCP state machine, UDP statelessness, port analysis  
🔄 Layer 4 (Application)    — DNS behavioral analysis, HTTP C2 patterns, TLS fingerprinting
🔄 Endpoint Correlation      — Process-to-network binding, parent-child relationships
```

**The philosophy**: You can't hunt what you don't understand at the packet level.  
Every detector in this tool has an explanation of *why* the logic works, not just *what* it does.

---

## 📦 Requirements

```txt
flask>=2.0
scapy>=2.5
openpyxl>=3.0
pandas>=1.3
geoip2>=4.0
maxminddb>=2.0
requests>=2.28
```

---

## ⚠️ Important Notes

> 🔒 **For Educational and Authorized Use Only**  
> Only analyze network traffic you own or have explicit written permission to analyze.  
> The synthetic attack PCAPs are generated locally — no real systems are targeted.

> 🪟 **Windows Users**  
> Wireshark must be installed for the Npcap driver (required by Scapy for live capture).  
> File analysis works without Npcap.

> 🔵 **IPv6 Support**  
> Full IPv6 parsing including ICMPv6, NDP, and IPv6-in-IPv4 tunneling detection.  
> All analyzers are None-safe for mixed IPv4/IPv6 captures.

---

## 🗺️ Roadmap

- [ ] 🔴 **Live Capture Mode** — Real-time interface capture + analysis
- [ ] 🟠 **JA3/JA3S Fingerprinting** — TLS client/server fingerprinting
- [ ] 🟠 **DNS Behavioral Scoring** — Entropy + TTL + NXDOMAIN ratio + beacon detection
- [ ] 🟡 **Zeek Log Integration** — Native Zeek conn.log / dns.log / http.log parsing  
- [ ] 🟡 **MITRE Navigator Export** — Export detections as ATT&CK Navigator layer
- [ ] 🟢 **Sigma Rule Generator** — Auto-generate Sigma rules from detected patterns
- [ ] 🟢 **Timeline View** — Attack progression visualization across time
- [ ] 🔵 **Multi-PCAP Correlation** — Cross-file session linking

---

## 👤 Author

<div align="center">

*Learning threat hunting one packet at a time.*

<br>

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/s-yuvan-shankar/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github)](https://github.com/Darkydeliver)

</div>

---

<div align="center">

```
If a packet crossed your network and you didn't understand it,
the attacker already won.
```

⭐ **Star this repo if it helped you think like a threat hunter** ⭐

</div>
