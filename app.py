"""
app.py

Flask web server for the TCP/IP Traffic Analyzer.
Runs locally on http://localhost:5000

Routes:
  GET  /              → Main dashboard (upload page)
  POST /analyze       → Upload PCAP and run all 4 modules
  GET  /results/<id>  → View analysis results
  GET  /api/results/<id> → Raw JSON results (for JS frontend)
"""

import os
import uuid
import json
import threading
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename

# ── Import all analyzer modules ───────────────────────────────
from analyzer.pcap_parser   import PCAPParser
from analyzer.traffic_stats import TrafficStats
from analyzer.port_scan     import PortScanDetector
from analyzer.geo_flag      import GeoFlagger
from analyzer.correlator    import Correlator

# ─────────────────────────────────────────────────────────────
# APP CONFIGURATION
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max upload

# ── Register Investigation Lab blueprint ──────────────────────
from lab_routes import lab as lab_blueprint
app.register_blueprint(lab_blueprint)

UPLOAD_FOLDER  = "uploads"
RESULTS_FOLDER = "results"
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}

os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# In-memory job tracker: job_id → status/results
jobs = {}


# ─────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def run_analysis(job_id, filepath):
    """
    Run all 4 analysis modules in background thread.
    Updates jobs[job_id] with progress and final results.
    """
    try:
        jobs[job_id]["status"]   = "running"
        jobs[job_id]["progress"] = 0
        jobs[job_id]["stage"]    = "Parsing PCAP file..."

        # ── Step 1: Parse PCAP ────────────────────────────────
        parser = PCAPParser(filepath)
        parser.load().parse()
        parsed   = parser.get_parsed()
        summary  = parser.get_summary()

        jobs[job_id]["progress"] = 20
        jobs[job_id]["stage"]    = "Analyzing traffic statistics..."

        # ── Step 2: Traffic Stats ─────────────────────────────
        stats_engine = TrafficStats(parsed)
        stats        = stats_engine.analyze()

        jobs[job_id]["progress"] = 40
        jobs[job_id]["stage"]    = "Detecting port scans and attacks..."

        # ── Step 3: Port Scan Detection ───────────────────────
        detector  = PortScanDetector(parsed)
        scan_findings = detector.detect()

        jobs[job_id]["progress"] = 60
        jobs[job_id]["stage"]    = "Geolocating suspicious IPs..."

        # ── Step 4: Geo Flagging ──────────────────────────────
        flagger     = GeoFlagger(parsed)
        geo_results = flagger.analyze()

        jobs[job_id]["progress"] = 80
        jobs[job_id]["stage"]    = "Correlating attack timelines..."

        # ── Step 5: Correlation ───────────────────────────────
        correlator = Correlator(parsed)
        chains     = correlator.correlate()

        jobs[job_id]["progress"] = 95
        jobs[job_id]["stage"]    = "Finalizing report..."

        # ── Serialize sets for JSON ───────────────────────────
        for chain in chains:
            for event in chain.get("events", []):
                if "flags_seen" in event and isinstance(event["flags_seen"], set):
                    event["flags_seen"] = list(event["flags_seen"])
            for stage in chain.get("stages", []):
                pass  # stages are already dicts

        # ── Build final results ───────────────────────────────
        results = {
            "job_id":       job_id,
            "filename":     summary.get("filename", "unknown"),
            "analyzed_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary":      summary,
            "stats":        stats,
            "scan_findings": [
                {k: (list(v) if isinstance(v, set) else v)
                 for k, v in f.items() if k != "explanation"}
                for f in scan_findings
            ],
            "scan_findings_full": [
                {k: (list(v) if isinstance(v, set) else v)
                 for k, v in f.items()}
                for f in scan_findings
            ],
            "geo_results":  geo_results,
            "chains":       chains,
            "threat_count": len([c for c in chains if c["is_suspicious"]]),
            "critical_count": len([f for f in scan_findings if f.get("severity") == "CRITICAL"]),
        }

        # Save to disk
        result_path = os.path.join(RESULTS_FOLDER, f"{job_id}.json")
        with open(result_path, "w") as f:
            json.dump(results, f, indent=2, default=str)

        jobs[job_id]["status"]   = "complete"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["stage"]    = "Analysis complete!"
        jobs[job_id]["results"]  = results

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"]  = str(e)
        import traceback
        jobs[job_id]["traceback"] = traceback.format_exc()


# ─────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Main upload page."""
    recent_jobs = [
        (jid, j) for jid, j in jobs.items()
        if j["status"] == "complete"
    ][-5:]  # Last 5 completed jobs
    return render_template("index.html", recent_jobs=recent_jobs)


@app.route("/analyze", methods=["POST"])
def analyze():
    """Handle PCAP file upload and start analysis."""
    if "pcap_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["pcap_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Upload .pcap, .pcapng, or .cap"}), 400

    # Save uploaded file
    filename  = secure_filename(file.filename)
    job_id    = str(uuid.uuid4())[:8]
    filepath  = os.path.join(UPLOAD_FOLDER, f"{job_id}_{filename}")
    file.save(filepath)

    # Create job entry
    jobs[job_id] = {
        "status":   "queued",
        "progress": 0,
        "stage":    "Queued...",
        "filename": filename,
        "filepath": filepath,
        "started":  datetime.now().strftime("%H:%M:%S"),
    }

    # Run analysis in background thread
    thread = threading.Thread(target=run_analysis, args=(job_id, filepath))
    thread.daemon = True
    thread.start()

    return jsonify({"job_id": job_id, "status": "started"})


@app.route("/status/<job_id>")
def status(job_id):
    """Poll job status (called by frontend every second)."""
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404

    job = jobs[job_id]
    response = {
        "status":   job["status"],
        "progress": job.get("progress", 0),
        "stage":    job.get("stage", ""),
    }

    if job["status"] == "error":
        response["error"] = job.get("error", "Unknown error")

    return jsonify(response)


@app.route("/results/<job_id>")
def results(job_id):
    """Render results dashboard page."""
    if job_id not in jobs or jobs[job_id]["status"] != "complete":
        return redirect(url_for("index"))
    return render_template("index.html", job_id=job_id, view="results")


@app.route("/api/results/<job_id>")
def api_results(job_id):
    """Return full results as JSON (used by frontend JS)."""
    # Try memory first
    if job_id in jobs and jobs[job_id]["status"] == "complete":
        return jsonify(jobs[job_id]["results"])

    # Try disk
    result_path = os.path.join(RESULTS_FOLDER, f"{job_id}.json")
    if os.path.exists(result_path):
        with open(result_path) as f:
            return jsonify(json.load(f))

    return jsonify({"error": "Results not found"}), 404


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  TCP/IP Traffic Analyzer")
    print("  Starting server at http://localhost:5000")
    print("  Press Ctrl+C to stop")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
