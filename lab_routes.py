"""
lab_routes.py  —  Investigation Lab Flask Blueprint

Supports: .pcap  .pcapng  .cap  .csv  .xlsx  .xls  .log  .txt

Key fixes:
  - Packet table always loads (filter bugs fixed)
  - CSV/XLSX/log/txt full parsing pipeline
  - IP filter uses partial match (prefix works)
  - findings preserve full knowledge+quiz for Learn panel
"""

import os, json, uuid, threading, csv, io
from datetime import datetime
from flask import Blueprint, request, jsonify, render_template
from werkzeug.utils import secure_filename
from collections import defaultdict

from analyzer.pcap_parser      import PCAPParser
from analyzer.attack_detector  import AttackDetector

lab = Blueprint("lab", __name__, url_prefix="/lab")

UPLOAD_FOLDER  = "uploads"
RESULTS_FOLDER = "results"
LAB_PCAPS_DIR  = os.path.join("static", "lab_pcaps")

PCAP_EXT  = {"pcap", "pcapng", "cap"}
TABLE_EXT = {"csv", "xlsx", "xls"}
LOG_EXT   = {"log", "txt"}
ALL_EXT   = PCAP_EXT | TABLE_EXT | LOG_EXT

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

lab_jobs = {}


# ═══════════════════════════════════════════════════════════════
# CSV / XLSX / LOG PARSERS
# ═══════════════════════════════════════════════════════════════

def parse_csv_log(filepath, ext):
    rows = []

    if ext in ("xlsx", "xls"):
        try:
            import openpyxl
            wb   = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
            ws   = wb.active
            data = list(ws.values)
            if not data:
                return [_err("Empty spreadsheet")]
            headers = [str(h).strip().lower().replace(" ","_") if h else f"col{i}"
                       for i, h in enumerate(data[0])]
            for row in data[1:]:
                rows.append(dict(zip(headers,
                    [str(v) if v is not None else "" for v in row])))
        except ImportError:
            try:
                import pandas as pd
                df = pd.read_excel(filepath)
                df.columns = [c.strip().lower().replace(" ","_") for c in df.columns]
                rows = df.fillna("").astype(str).to_dict("records")
            except Exception as e:
                return [_err(f"Install openpyxl or pandas to read XLSX. ({e})")]

    elif ext == "csv":
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # Auto-detect delimiter
        delim = ","
        for d in ["\t", ";", "|"]:
            if content.count(d) > content.count(","):
                delim = d; break
        reader = csv.DictReader(io.StringIO(content), delimiter=delim)
        for row in reader:
            rows.append({k.strip().lower().replace(" ","_"): (v or "").strip()
                         for k, v in row.items() if k})

    else:  # .log / .txt
        rows = _parse_text_log(filepath)

    if not rows:
        return [_err("File is empty or unreadable")]

    packets = []
    for i, row in enumerate(rows):
        p = _row_to_packet(i, row)
        if p:
            packets.append(p)
    return packets or [_err("No parseable rows found")]


def _parse_text_log(filepath):
    import re
    rows = []
    ip_re   = r'\b(\d{1,3}(?:\.\d{1,3}){3})\b'
    port_re = r':(\d{2,5})\b'
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips   = re.findall(ip_re,   line)
            ports = re.findall(port_re, line)
            rows.append({
                "src_ip":   ips[0]   if len(ips)   > 0 else "",
                "dst_ip":   ips[1]   if len(ips)   > 1 else "",
                "src_port": ports[0] if len(ports) > 0 else "",
                "dst_port": ports[1] if len(ports) > 1 else "",
                "protocol": _proto_from_text(line),
                "info":     line[:150],
            })
    return rows


def _proto_from_text(line):
    ll = line.lower()
    for p in ["https","http","ssh","dns","ftp","smtp","tcp","udp","icmp","arp","rdp"]:
        if p in ll:
            return p.upper()
    return "OTHER"


# Field name alias table — handles Wireshark CSV, Zeek, Suricata, generic logs
_ALIASES = {
    "src_ip":    ["src_ip","source","src","source_ip","ip_src","client_ip",
                  "srcip","id.orig_h","saddr","source address","originating_ip"],
    "dst_ip":    ["dst_ip","destination","dst","dest_ip","ip_dst","server_ip",
                  "dstip","id.resp_h","daddr","destination address"],
    "src_port":  ["src_port","sport","source_port","srcport","id.orig_p","source port"],
    "dst_port":  ["dst_port","dport","dest_port","dstport","id.resp_p","destination port",
                  "port"],
    "protocol":  ["protocol","proto","layer_4_protocol","service","transport",
                  "highest_layer","protocol_(basic)","protocol (basic)"],
    "length":    ["length","len","pkt_len","size","bytes","frame.len",
                  "frame_length","frame length","total_length"],
    "info":      ["info","description","message","summary","sig_name","alert",
                  "label","event","details","log","raw","content"],
    "time_str":  ["time","timestamp","ts","datetime","date_time","frame.time",
                  "frame_time","frame time","time_(seconds)"],
    "tcp_flags": ["tcp_flags","flags","flag","tcp.flags","tcp flags","tcp_flag"],
    "ttl":       ["ttl","time_to_live","ip_ttl","ip.ttl","hop_limit"],
}


def _get(row, field):
    for alias in _ALIASES.get(field, []):
        v = row.get(alias, "")
        if v and str(v).strip() not in ("", "-", "N/A", "nan", "None"):
            return str(v).strip()
    return ""


def _safe_int(v):
    try: return int(float(v)) if v else None
    except: return None


def _port_to_proto(port):
    return {80:"HTTP",443:"HTTPS",22:"SSH",21:"FTP",25:"SMTP",53:"DNS",
            3389:"RDP",23:"Telnet",110:"POP3",143:"IMAP",8080:"HTTP",
            67:"DHCP",123:"NTP"}.get(port, "TCP")


def _row_to_packet(index, row):
    src_ip = _get(row, "src_ip")
    dst_ip = _get(row, "dst_ip")
    if not src_ip and not dst_ip:
        return None

    proto = _get(row, "protocol").upper()
    if not proto:
        dp = _safe_int(_get(row, "dst_port")) or 0
        proto = _port_to_proto(dp)

    time_val = _get(row, "time_str") or f"row-{index+1}"
    info     = _get(row, "info")     or f"{proto} {src_ip} → {dst_ip}"
    flags    = _get(row, "tcp_flags")

    private  = ("10.","192.168.","172.","127.","0.")
    is_ext   = bool(src_ip and not any(src_ip.startswith(p) for p in private))

    return {
        "index":       index,
        "timestamp":   index * 0.1,
        "time_str":    time_val,
        "src_ip":      src_ip or "0.0.0.0",
        "dst_ip":      dst_ip or "0.0.0.0",
        "src_port":    _safe_int(_get(row, "src_port")),
        "dst_port":    _safe_int(_get(row, "dst_port")),
        "protocol":    proto or "OTHER",
        "length":      _safe_int(_get(row, "length")) or 0,
        "frame_length":_safe_int(_get(row, "length")) or 0,
        "tcp_flags":   flags,
        "flags":       flags,
        "ttl":         _safe_int(_get(row, "ttl")),
        "info":        info[:200],
        "is_external": is_ext,
        # Store original CSV row for the detail panel
        "csv_row":     {k: str(v) for k, v in row.items()},
        # Null out PCAP-only fields
        "ip": None, "tcp": None, "udp": None, "icmp": None,
        "dns": None, "eth": None, "arp": None,
        "payload": None, "payload_dump": [], "payload_len": 0,
    }


def _err(msg):
    return {"index":0,"timestamp":0,"time_str":"00:00:00",
            "src_ip":"0.0.0.0","dst_ip":"0.0.0.0","protocol":"OTHER",
            "length":0,"info":f"ERROR: {msg}","tcp_flags":"","flags":"",
            "ttl":None,"is_external":False,"frame_length":0,
            "src_port":None,"dst_port":None,
            "ip":None,"tcp":None,"udp":None,"icmp":None,
            "dns":None,"eth":None,"arp":None,
            "payload":None,"payload_dump":[],"payload_len":0}


def _make_summary(packets, filename):
    from collections import Counter
    protos = Counter(p.get("protocol","OTHER") for p in packets)
    srcs   = Counter(p.get("src_ip","")        for p in packets)
    dsts   = Counter(p.get("dst_ip","")        for p in packets)
    ts     = [p.get("timestamp",0) for p in packets]
    return {
        "filename":         filename,
        "total_packets":    len(packets),
        "total_bytes_kb":   round(sum(p.get("length",0) for p in packets)/1024, 2),
        "duration_sec":     round(max(ts)-min(ts), 2) if ts else 0,
        "start_time":       packets[0].get("time_str","")  if packets else "",
        "end_time":         packets[-1].get("time_str","") if packets else "",
        "unique_src_ips":   len(set(p.get("src_ip","") for p in packets)),
        "external_packets": sum(1 for p in packets if p.get("is_external")),
        "protocol_counts":  dict(protos.most_common(15)),
        "top_talkers":      srcs.most_common(10),
        "top_destinations": dsts.most_common(10),
    }


# ═══════════════════════════════════════════════════════════════
# BACKGROUND ANALYSIS THREAD
# ═══════════════════════════════════════════════════════════════

def run_lab_analysis(job_id, filepath, ext):
    try:
        lab_jobs[job_id].update({"status":"running","progress":5,
                                  "stage":"Reading file..."})

        if ext in PCAP_EXT:
            lab_jobs[job_id]["stage"] = "Parsing PCAP..."
            parser  = PCAPParser(filepath)
            parser.load().parse()
            parsed  = parser.get_parsed()
            summary = parser.get_summary()
        else:
            lab_jobs[job_id]["stage"] = f"Parsing {ext.upper()} log..."
            parsed  = parse_csv_log(filepath, ext)
            summary = _make_summary(parsed, os.path.basename(filepath))

        lab_jobs[job_id].update({"progress":45,
            "stage":f"Parsed {len(parsed)} records. Detecting attacks..."})

        detector = AttackDetector(parsed)
        findings = detector.detect_all()

        lab_jobs[job_id].update({"progress":80, "stage":"Building IP index..."})

        ip_index = defaultdict(list)
        for p in parsed:
            if p.get("src_ip"): ip_index[p["src_ip"]].append(p.get("index",0))
            if p.get("dst_ip"): ip_index[p["dst_ip"]].append(p.get("index",0))

        # Serialise — preserve all fields including knowledge/quiz
        clean = {}
        for k, v in findings.items():
            clean[k] = {fk: list(fv) if isinstance(fv, set) else fv
                        for fk, fv in v.items()}

        result = {
            "job_id":        job_id,
            "filename":      summary.get("filename","unknown"),
            "file_type":     ext,
            "analyzed_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary":       summary,
            "packets":       parsed,
            "findings":      clean,
            "ip_index":      dict(ip_index),
            "total_packets": len(parsed),
        }

        path = os.path.join(RESULTS_FOLDER, f"lab_{job_id}.json")
        with open(path, "w") as f:
            json.dump(result, f, default=str)

        lab_jobs[job_id].update({"status":"complete","progress":100,
            "stage":f"Done! {len(parsed)} records analysed.","result":result})

    except Exception as e:
        import traceback
        lab_jobs[job_id].update({"status":"error","error":str(e),
                                  "traceback":traceback.format_exc()})


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def get_result(job_id):
    if job_id in lab_jobs and "result" in lab_jobs[job_id]:
        return lab_jobs[job_id]["result"]
    path = os.path.join(RESULTS_FOLDER, f"lab_{job_id}.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def get_ext(filename):
    return filename.rsplit(".",1)[1].lower() if "." in filename else "pcap"


# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════

@lab.route("/")
def lab_index():
    return render_template("lab.html")


@lab.route("/upload", methods=["POST"])
def lab_upload():
    sample = request.form.get("sample_file")

    if sample:
        filename = secure_filename(sample)
        filepath = os.path.join(LAB_PCAPS_DIR, filename)
        if not os.path.exists(filepath):
            return jsonify({"error": f"Sample not found: {sample}"}), 404
        ext = get_ext(filename)

    elif "pcap_file" in request.files:
        file = request.files["pcap_file"]
        if not file.filename:
            return jsonify({"error": "No file selected"}), 400
        ext = get_ext(file.filename)
        if ext not in ALL_EXT:
            return jsonify({"error":
                f"Unsupported type '.{ext}'. Supported: "
                + ", ".join(sorted(ALL_EXT))}), 400
        jid      = str(uuid.uuid4())[:8]
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, f"lab_{jid}_{filename}")
        file.save(filepath)
    else:
        return jsonify({"error": "No file provided"}), 400

    job_id = str(uuid.uuid4())[:8]
    lab_jobs[job_id] = {"status":"queued","progress":0,"stage":"Queued...",
                         "filename":filename,
                         "started":datetime.now().strftime("%H:%M:%S")}

    t = threading.Thread(target=run_lab_analysis, args=(job_id, filepath, ext))
    t.daemon = True
    t.start()

    return jsonify({"job_id":job_id,"status":"started",
                    "filename":filename,"file_type":ext})


@lab.route("/status/<job_id>")
def lab_status(job_id):
    if job_id not in lab_jobs:
        return jsonify({"error":"Job not found"}), 404
    j = lab_jobs[job_id]
    r = {"status":j["status"],"progress":j.get("progress",0),
         "stage":j.get("stage",""),"filename":j.get("filename","")}
    if j["status"] == "error":
        r["error"] = j.get("error","Unknown error")
    return jsonify(r)


@lab.route("/api/packets/<job_id>")
def api_packets(job_id):
    result = get_result(job_id)
    if not result:
        return jsonify({"error":"Not found","packets":[],"total":0,
                        "page":1,"per_page":150,"total_pages":0,"filtered":False}), 404

    packets = result["packets"]

    # ── Filters ───────────────────────────────────────────────
    f_ip    = request.args.get("filter_ip",    "").strip()
    f_proto = request.args.get("filter_proto", "").strip().upper()
    f_flag  = request.args.get("filter_flag",  "").strip().upper()
    f_port  = request.args.get("filter_port",  "").strip()
    f_text  = request.args.get("filter_text",  "").strip().lower()

    if f_ip:
        packets = [p for p in packets
                   if f_ip in (p.get("src_ip","") or "")
                   or f_ip in (p.get("dst_ip","") or "")]
    if f_proto:
        packets = [p for p in packets
                   if f_proto in (p.get("protocol","") or "").upper()]
    if f_flag:
        packets = [p for p in packets
                   if f_flag in (p.get("tcp_flags","") or "").upper()]
    if f_port:
        try:
            port = int(f_port)
            packets = [p for p in packets
                       if p.get("src_port") == port or p.get("dst_port") == port]
        except ValueError:
            pass
    if f_text:
        packets = [p for p in packets
                   if f_text in (p.get("info","")   or "").lower()
                   or f_text in (p.get("src_ip","") or "").lower()
                   or f_text in (p.get("dst_ip","") or "").lower()
                   or f_text in (p.get("protocol","") or "").lower()]

    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(500, int(request.args.get("per_page", 150)))
    total    = len(packets)
    start    = (page - 1) * per_page

    slim = [{
        "index":     p.get("index", 0),
        "time_str":  p.get("time_str", ""),
        "src_ip":    p.get("src_ip",  "") or "",
        "dst_ip":    p.get("dst_ip",  "") or "",
        "src_port":  p.get("src_port"),
        "dst_port":  p.get("dst_port"),
        "protocol":  p.get("protocol", "OTHER") or "OTHER",
        "length":    p.get("length", p.get("frame_length", 0)) or 0,
        "tcp_flags": p.get("tcp_flags", "") or "",
        "ttl":       p.get("ttl"),
        "info":      (p.get("info","") or "")[:120],
        "is_external": bool(p.get("is_external", False)),
    } for p in packets[start: start + per_page]]

    return jsonify({
        "packets":    slim,
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page) if total else 1,
        "filtered":   total != result["total_packets"],
        "file_type":  result.get("file_type","pcap"),
    })


@lab.route("/api/packet/<job_id>/<int:pkt_index>")
def api_packet_detail(job_id, pkt_index):
    result = get_result(job_id)
    if not result:
        return jsonify({"error":"Not found"}), 404
    matches = [p for p in result["packets"] if p.get("index") == pkt_index]
    if not matches:
        return jsonify({"error":"Packet not found"}), 404
    return jsonify(matches[0])


@lab.route("/api/attacks/<job_id>")
def api_attacks(job_id):
    result = get_result(job_id)
    if not result:
        return jsonify({"error":"Not found"}), 404
    findings   = result["findings"]
    detected   = {k:v for k,v in findings.items() if v.get("detected")}
    undetected = {k:v for k,v in findings.items() if not v.get("detected")}
    return jsonify({"detected":detected,"undetected":undetected,
                    "detected_count":len(detected),"total_checks":len(findings),
                    "file_type":result.get("file_type","pcap")})


@lab.route("/api/ip/<job_id>/<ip>")
def api_ip_profile(job_id, ip):
    result = get_result(job_id)
    if not result:
        return jsonify({"error":"Not found"}), 404

    packets = result["packets"]
    ip_pkts = [p for p in packets
               if p.get("src_ip")==ip or p.get("dst_ip")==ip]
    if not ip_pkts:
        return jsonify({"error":f"IP {ip} not found"}), 404

    protocols  = defaultdict(int)
    dst_ports  = defaultdict(int)
    flags_seen = defaultdict(int)
    conns_to, conns_from = set(), set()
    bsent = brecv = 0

    for p in ip_pkts:
        protocols[p.get("protocol","OTHER")] += 1
        if p.get("src_ip")==ip:
            bsent += p.get("length",0)
            if p.get("dst_ip"): conns_to.add(p["dst_ip"])
            if p.get("dst_port"): dst_ports[str(p["dst_port"])] += 1
        else:
            brecv += p.get("length",0)
            if p.get("src_ip"): conns_from.add(p["src_ip"])
        for flag in (p.get("tcp_flags","") or "").split("+"):
            if flag.strip(): flags_seen[flag.strip()] += 1

    timeline = [{"index":p.get("index"),"time":p.get("time_str",""),
                 "src":p.get("src_ip"),"dst":p.get("dst_ip"),
                 "proto":p.get("protocol",""),"flags":p.get("tcp_flags",""),
                 "length":p.get("length",0),"info":(p.get("info","") or "")[:80]}
                for p in ip_pkts[:300]]

    private = ("10.","192.168.","172.","127.")
    return jsonify({
        "ip":ip,"is_external":not any(ip.startswith(p) for p in private),
        "total_packets":len(ip_pkts),
        "bytes_sent_kb":round(bsent/1024,2),"bytes_recv_kb":round(brecv/1024,2),
        "protocols":dict(sorted(protocols.items(),key=lambda x:-x[1])),
        "dst_ports":dict(sorted(dst_ports.items(),key=lambda x:-x[1])[:10]),
        "flags_seen":dict(flags_seen),
        "connects_to":sorted(conns_to)[:20],
        "receives_from":sorted(conns_from)[:20],
        "timeline":timeline,
    })


@lab.route("/api/quiz/<attack_type>")
def api_quiz(attack_type):
    from analyzer.attack_detector import ATTACK_KNOWLEDGE
    k = ATTACK_KNOWLEDGE.get(attack_type.upper())
    if not k:
        return jsonify({"error":f"Unknown attack: {attack_type}"}), 404
    quiz = k.get("quiz",[])
    return jsonify({
        "attack_type":attack_type,"title":k.get("title",attack_type),
        "questions":[{"number":i+1,"question":q["q"],"options":q["options"]}
                     for i,q in enumerate(quiz)],
        "total":len(quiz),
    })


@lab.route("/api/quiz/check", methods=["POST"])
def api_quiz_check():
    from analyzer.attack_detector import ATTACK_KNOWLEDGE
    data = request.get_json()
    k    = ATTACK_KNOWLEDGE.get((data.get("attack_type","")).upper())
    if not k:
        return jsonify({"error":"Unknown attack"}), 404
    quiz = k.get("quiz",[])
    n    = data.get("question",1) - 1
    ua   = data.get("answer")
    if not (0 <= n < len(quiz)):
        return jsonify({"error":"Out of range"}), 400
    q = quiz[n]
    ci = q["answer"]
    return jsonify({"correct":ua==ci,"correct_index":ci,
                    "correct_text":q["options"][ci],"explanation":q["explanation"],
                    "your_answer":q["options"][ua] if ua is not None else None})


@lab.route("/api/samples")
def api_samples():
    if not os.path.exists(LAB_PCAPS_DIR):
        return jsonify({"samples":[],"message":
                        "Run: python analyzer/lab_pcap_generator.py"})

    DESC = {
        "00_mega_combined.pcap":     "All 20 attacks combined — Advanced investigation",
        "01_syn_flood.pcap":         "SYN Flood — 500 SYN, no ACK completion",
        "02_rst_injection.pcap":     "RST Injection — Forged RST mid-session",
        "03_tcp_session_hijack.pcap":"TCP Session Hijack — Seq number anomalies",
        "04_udp_flood.pcap":         "UDP Flood — 600 packets to random ports",
        "05_port_scan.pcap":         "Port Scan — SYN scan across 200 ports",
        "06_dns_tunneling.pcap":     "DNS Tunneling — High-entropy subdomains",
        "07_dns_amplification.pcap": "DNS Amplification — Huge ANY query responses",
        "08_fast_flux_dns.pcap":     "Fast-Flux DNS — Same domain, 20 different IPs",
        "09_dga_domains.pcap":       "DGA Domains — 60 algorithmically generated names",
        "10_ip_spoofing.pcap":       "IP Spoofing — Private IPs to external hosts",
        "11_icmp_tunneling.pcap":    "ICMP Tunneling — Oversized ICMP payloads",
        "12_ip_fragmentation.pcap":  "IP Fragmentation — Overlapping fragment offsets",
        "13_arp_spoofing.pcap":      "ARP Spoofing — Gateway MAC poisoning",
        "14_mac_flooding.pcap":      "MAC Flooding — 500 fake MACs",
        "15_http_attacks.pcap":      "HTTP Attacks — Smuggling + Slowloris",
        "16_smtp_exfiltration.pcap": "SMTP Exfiltration — Plaintext email + attachment",
        "17_ftp_exfiltration.pcap":  "FTP Exfiltration — Plaintext creds + file",
        "18_slowloris.pcap":         "Slowloris — 50 half-open HTTP connections",
        "19_ssl_stripping.pcap":     "SSL Stripping — HTTPS→HTTP downgrade",
        "20_bgp_hijacking.pcap":     "BGP Hijacking — Rogue AS path announcement",
    }

    exts  = tuple(f".{e}" for e in ALL_EXT)
    files = sorted(f for f in os.listdir(LAB_PCAPS_DIR) if f.endswith(exts))
    return jsonify({"samples":[{
        "filename":   f,
        "description":DESC.get(f, f),
        "size_kb":    round(os.path.getsize(os.path.join(LAB_PCAPS_DIR,f))/1024,1),
        "is_mega":    f.startswith("00_"),
        "file_type":  get_ext(f),
    } for f in files]})
