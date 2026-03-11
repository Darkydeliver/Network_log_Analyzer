"""
setup_check.py
Run this first to verify your environment is ready.
Usage: python setup_check.py
"""

import sys
import subprocess
import importlib

REQUIRED_PACKAGES = [
    ("flask", "Flask"),
    ("scapy", "Scapy"),
    ("requests", "Requests"),
    ("pandas", "Pandas"),
    ("plotly", "Plotly"),
]

def check_python_version():
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"  [OK] Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print(f"  [FAIL] Python 3.8+ required. You have {version.major}.{version.minor}")
        return False

def check_package(import_name, display_name):
    try:
        importlib.import_module(import_name)
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", "unknown")
        print(f"  [OK] {display_name} ({version})")
        return True
    except ImportError:
        print(f"  [MISSING] {display_name} — run: pip install -r requirements.txt")
        return False

def check_wireshark():
    """Check if tshark (Wireshark CLI) is accessible — needed for pyshark fallback."""
    import shutil
    tshark = shutil.which("tshark")
    if tshark:
        print(f"  [OK] tshark found at: {tshark}")
        return True
    else:
        print("  [WARN] tshark not in PATH — Wireshark is installed but tshark may need to be added to PATH.")
        print("         Typical path: C:\\Program Files\\Wireshark\\tshark.exe")
        print("         Scapy will still work without this.")
        return False

def main():
    print("=" * 50)
    print("  TCP/IP Traffic Analyzer — Setup Check")
    print("=" * 50)

    all_ok = True

    print("\n[1] Python Version:")
    all_ok &= check_python_version()

    print("\n[2] Required Packages:")
    for import_name, display_name in REQUIRED_PACKAGES:
        result = check_package(import_name, display_name)
        all_ok &= result

    print("\n[3] Wireshark / tshark:")
    check_wireshark()  # Warning only, not blocking

    print("\n" + "=" * 50)
    if all_ok:
        print("  All checks passed! You're ready to go.")
        print("  Next step: python synthetic_pcap_generator.py")
    else:
        print("  Some checks failed. Fix the issues above, then re-run.")
        print("  Quick fix: pip install -r requirements.txt")
    print("=" * 50)

if __name__ == "__main__":
    main()
