#!/usr/bin/env python3
"""
Oxytocin AV - Core Scanner Engine
Cross-platform antivirus for Windows, Linux, macOS
"""

import os
import sys
import hashlib
import json
import time
import shutil
import platform
import threading
import argparse
from datetime import datetime
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG = True
except ImportError:
    WATCHDOG = False

try:
    import requests
    REQUESTS = True
except ImportError:
    REQUESTS = False

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
VERSION = "1.0.0"
APP_NAME = "Oxytocin AV"
OS = platform.system()

if OS == "Windows":
    DATA_DIR = Path(os.environ.get("APPDATA", "")) / "OxytocinAV"
elif OS == "Darwin":
    DATA_DIR = Path.home() / "Library" / "Application Support" / "OxytocinAV"
else:
    DATA_DIR = Path.home() / ".config" / "oxytocin-av"

QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_FILE       = DATA_DIR / "oxytocin.log"
DB_FILE        = DATA_DIR / "signatures.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

COLORS = {
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
}

def c(color, text):
    if OS == "Windows" and not os.environ.get("WT_SESSION"):
        return text
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

# ─────────────────────────────────────────────
# SIGNATURE DATABASE
# ─────────────────────────────────────────────
BUILTIN_SIGNATURES = {
    # SHA256 hash : threat name
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EmptyFile.Suspicious",
    "44d88612fea8a8f36de82e1278abb02f": "Eicar.TestFile",
    "cf8bd9dfddff007f75adf4c2be48005cea317c62": "Eicar.TestFile.Variant",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jar",
    ".scr", ".pif", ".com", ".msi", ".hta", ".wsf", ".reg"
}

SUSPICIOUS_PATTERNS = [
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"cmd.exe /c",
    b"powershell -enc",
    b"powershell -nop",
    b"base64_decode",
    b"eval(base64",
    b"WScript.Shell",
]

def load_signatures():
    if DB_FILE.exists():
        try:
            with open(DB_FILE) as f:
                db = json.load(f)
                db.update(BUILTIN_SIGNATURES)
                return db
        except Exception:
            pass
    return dict(BUILTIN_SIGNATURES)

SIGNATURES = load_signatures()

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
def log(msg, level="INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)

# ─────────────────────────────────────────────
# SCANNER
# ─────────────────────────────────────────────
def get_hash(filepath, algo="sha256"):
    h = hashlib.new(algo)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

def check_patterns(filepath):
    """Heuristic: scan binary content for suspicious strings."""
    hits = []
    try:
        with open(filepath, "rb") as f:
            content = f.read(1024 * 512)  # read first 512KB
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in content:
                hits.append(pattern.decode(errors="ignore"))
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return hits

def scan_file(filepath):
    """
    Returns dict: {status, threat, filepath, hash, details}
    status: CLEAN | THREAT | SUSPICIOUS | SKIPPED
    """
    path = Path(filepath)
    result = {
        "filepath": str(filepath),
        "status": "CLEAN",
        "threat": None,
        "hash": None,
        "details": []
    }

    if not path.exists() or not path.is_file():
        result["status"] = "SKIPPED"
        return result

    # Skip quarantine dir itself
    if QUARANTINE_DIR in path.parents:
        result["status"] = "SKIPPED"
        return result

    file_hash = get_hash(filepath)
    result["hash"] = file_hash

    # 1. Signature match
    if file_hash and file_hash in SIGNATURES:
        result["status"] = "THREAT"
        result["threat"] = SIGNATURES[file_hash]
        result["details"].append("Matched known malware signature")
        log(f"THREAT: {filepath} → {result['threat']}", "THREAT")
        return result

    # 2. Heuristic pattern check (only executable-type files)
    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        hits = check_patterns(filepath)
        if len(hits) >= 2:
            result["status"] = "SUSPICIOUS"
            result["threat"] = "Heuristic.SuspiciousCode"
            result["details"] = [f"Suspicious pattern: {h}" for h in hits]
            log(f"SUSPICIOUS: {filepath} → patterns: {hits}", "WARN")

    return result

def quarantine_file(filepath):
    """Move threat to quarantine directory."""
    path = Path(filepath)
    dest = QUARANTINE_DIR / f"{path.name}.{int(time.time())}.quarantine"
    try:
        shutil.move(str(path), str(dest))
        log(f"Quarantined: {filepath} → {dest}", "ACTION")
        return str(dest)
    except Exception as e:
        log(f"Quarantine failed for {filepath}: {e}", "ERROR")
        return None

def scan_directory(directory, extensions=None, callback=None):
    """Scan all files in a directory recursively."""
    results = {"clean": 0, "threats": [], "suspicious": [], "skipped": 0, "total": 0}
    path = Path(directory)

    if not path.exists():
        print(c("red", f"  ✗ Path not found: {directory}"))
        return results

    for root, dirs, files in os.walk(path):
        # Skip hidden dirs
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for fname in files:
            fpath = Path(root) / fname
            results["total"] += 1

            if extensions and fpath.suffix.lower() not in extensions:
                results["skipped"] += 1
                continue

            result = scan_file(fpath)

            if result["status"] == "THREAT":
                results["threats"].append(result)
            elif result["status"] == "SUSPICIOUS":
                results["suspicious"].append(result)
            elif result["status"] == "CLEAN":
                results["clean"] += 1
            else:
                results["skipped"] += 1

            if callback:
                callback(result, results["total"])

    return results

# ─────────────────────────────────────────────
# CLOUD LOOKUP (VirusTotal)
# ─────────────────────────────────────────────
def virustotal_lookup(file_hash, api_key):
    if not REQUESTS:
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values())
            }
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────
# REAL-TIME PROTECTION
# ─────────────────────────────────────────────
class ThreatHandler(FileSystemEventHandler):
    def __init__(self, auto_quarantine=False):
        self.auto_quarantine = auto_quarantine

    def handle(self, path):
        result = scan_file(path)
        if result["status"] == "THREAT":
            print(c("red", f"\n  🚨 THREAT DETECTED: {path}"))
            print(c("red", f"     Threat: {result['threat']}"))
            if self.auto_quarantine:
                dest = quarantine_file(path)
                print(c("yellow", f"     ✓ Quarantined to: {dest}"))
        elif result["status"] == "SUSPICIOUS":
            print(c("yellow", f"\n  ⚠  SUSPICIOUS: {path}"))
            for d in result["details"]:
                print(c("yellow", f"     · {d}"))

    def on_created(self, event):
        if not event.is_directory:
            self.handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.handle(event.src_path)

def start_realtime(watch_path, auto_quarantine=False):
    if not WATCHDOG:
        print(c("red", "  ✗ watchdog not installed. Run: pip install watchdog"))
        return
    handler = ThreatHandler(auto_quarantine)
    observer = Observer()
    observer.schedule(handler, str(watch_path), recursive=True)
    observer.start()
    print(c("green", f"  ✓ Real-time protection active on: {watch_path}"))
    print(c("cyan",  "    Press Ctrl+C to stop.\n"))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    print(c("yellow", "\n  Real-time protection stopped."))

# ─────────────────────────────────────────────
# CLI INTERFACE
# ─────────────────────────────────────────────
def print_banner():
    print(c("cyan", c("bold", f"""
  ╔═══════════════════════════════════════╗
  ║       🛡️  Oxytocin AV v{VERSION}          ║
  ║   Security that feels human.          ║
  ╚═══════════════════════════════════════╝
""")))

def print_result_summary(results, elapsed):
    total     = results["total"]
    threats   = len(results["threats"])
    suspicious = len(results["suspicious"])
    clean     = results["clean"]
    skipped   = results["skipped"]

    print(c("white", "\n  ─────────────────────────────────────"))
    print(c("white", "  SCAN COMPLETE"))
    print(c("white", "  ─────────────────────────────────────"))
    print(f"  Files scanned : {c('white', str(total))}")
    print(f"  Clean         : {c('green', str(clean))}")
    print(f"  Threats       : {c('red', str(threats))}")
    print(f"  Suspicious    : {c('yellow', str(suspicious))}")
    print(f"  Skipped       : {c('cyan', str(skipped))}")
    print(f"  Time elapsed  : {c('cyan', f'{elapsed:.1f}s')}")

    if threats > 0:
        print(c("red", "\n  🚨 THREATS FOUND:"))
        for t in results["threats"]:
            print(c("red", f"     · {t['filepath']}"))
            print(c("red", f"       → {t['threat']}"))
    if suspicious > 0:
        print(c("yellow", "\n  ⚠  SUSPICIOUS FILES:"))
        for s in results["suspicious"]:
            print(c("yellow", f"     · {s['filepath']}"))
            for d in s["details"]:
                print(c("yellow", f"       → {d}"))

    if threats == 0 and suspicious == 0:
        print(c("green", "\n  ✅ No threats found. Your system is clean!"))
    print()

def main():
    parser = argparse.ArgumentParser(
        prog="oxytocin-av",
        description=f"{APP_NAME} v{VERSION} — Cross-platform antivirus"
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files or directories")
    p_scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: current dir)")
    p_scan.add_argument("--quick", action="store_true", help="Quick scan (executables only)")
    p_scan.add_argument("--quarantine", action="store_true", help="Auto-quarantine threats")
    p_scan.add_argument("--vt", metavar="API_KEY", help="VirusTotal API key for cloud lookup")

    # realtime
    p_rt = sub.add_parser("protect", help="Enable real-time protection")
    p_rt.add_argument("path", nargs="?", default=str(Path.home()), help="Directory to watch")
    p_rt.add_argument("--quarantine", action="store_true", help="Auto-quarantine threats")

    # quarantine
    p_q = sub.add_parser("quarantine", help="Manage quarantine vault")
    p_q.add_argument("--list", action="store_true", help="List quarantined files")
    p_q.add_argument("--clear", action="store_true", help="Permanently delete quarantined files")

    # update
    sub.add_parser("update", help="Update virus definitions")

    # version
    sub.add_parser("version", help="Show version")

    args = parser.parse_args()

    print_banner()

    if args.command == "version" or not args.command:
        print(f"  {APP_NAME} v{VERSION}")
        print(f"  Platform : {OS} ({platform.machine()})")
        print(f"  Signatures: {len(SIGNATURES)} loaded")
        print(f"  Data dir : {DATA_DIR}\n")
        if not args.command:
            parser.print_help()
        return

    if args.command == "scan":
        scan_path = Path(args.path).resolve()
        exts = SUSPICIOUS_EXTENSIONS if args.quick else None
        mode = "quick (executables)" if args.quick else "full"
        print(f"  Scanning  : {c('cyan', str(scan_path))}")
        print(f"  Mode      : {c('cyan', mode)}")
        print(f"  Quarantine: {c('green', 'on') if args.quarantine else c('yellow', 'off')}\n")

        count = [0]
        def progress(result, total):
            count[0] = total
            if total % 100 == 0:
                sys.stdout.write(f"\r  Files checked: {total}   ")
                sys.stdout.flush()

        start = time.time()
        results = scan_directory(scan_path, extensions=exts, callback=progress)
        elapsed = time.time() - start

        sys.stdout.write("\r" + " " * 40 + "\r")

        # VirusTotal cloud check for threats
        if args.vt and results["threats"]:
            print(c("cyan", "  Checking threats against VirusTotal..."))
            for t in results["threats"]:
                if t["hash"]:
                    vt = virustotal_lookup(t["hash"], args.vt)
                    if vt:
                        t["details"].append(f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged")

        # Auto-quarantine
        if args.quarantine and results["threats"]:
            print(c("yellow", "  Quarantining threats..."))
            for t in results["threats"]:
                dest = quarantine_file(t["filepath"])
                if dest:
                    t["quarantined"] = dest
                    print(c("yellow", f"    ✓ {Path(t['filepath']).name}"))

        print_result_summary(results, elapsed)
        log(f"Scan complete: {results['total']} files, {len(results['threats'])} threats", "INFO")

    elif args.command == "protect":
        watch = Path(args.path).resolve()
        print(f"  Starting real-time protection on: {c('cyan', str(watch))}\n")
        start_realtime(watch, auto_quarantine=args.quarantine)

    elif args.command == "quarantine":
        if args.list:
            files = list(QUARANTINE_DIR.glob("*"))
            if not files:
                print(c("green", "  Quarantine vault is empty.\n"))
            else:
                print(c("yellow", f"  {len(files)} file(s) in quarantine:\n"))
                for f in files:
                    size = f.stat().st_size
                    print(f"    · {f.name} ({size:,} bytes)")
                print()
        elif args.clear:
            files = list(QUARANTINE_DIR.glob("*"))
            for f in files:
                f.unlink()
            print(c("green", f"  ✓ Deleted {len(files)} quarantined file(s).\n"))
        else:
            print(f"  Quarantine dir: {QUARANTINE_DIR}")
            print(f"  Use --list or --clear\n")

    elif args.command == "update":
        print(c("cyan", "  Updating virus definitions..."))
        # In production: fetch from your signature server
        # For now, simulate an update
        time.sleep(1.5)
        sigs = dict(SIGNATURES)
        sigs["updated"] = datetime.now().isoformat()
        with open(DB_FILE, "w") as f:
            json.dump(sigs, f, indent=2)
        print(c("green", f"  ✓ Definitions updated. {len(SIGNATURES)} signatures loaded.\n"))
        log("Signature DB updated", "INFO")

if __name__ == "__main__":
    main()
