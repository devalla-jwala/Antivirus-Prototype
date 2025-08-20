import os
import hashlib
import json
import shutil
from datetime import datetime

# Load signatures
with open("signatures.json", "r") as f:
    signatures = json.load(f)

quarantine_dir = "quarantine"
report_dir = "reports"
os.makedirs(quarantine_dir, exist_ok=True)
os.makedirs(report_dir, exist_ok=True)

def file_hash(filepath):
    """Return MD5 hash of a file."""
    h = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def is_suspicious(filepath):
    filename = os.path.basename(filepath).lower()

    # Extension check
    for ext in signatures["extensions"]:
        if filename.endswith(ext):
            return True, "Suspicious extension"

    # Double extension
    if "." in filename and filename.count(".") > 1:
        return True, "Double extension"

    # Large file check (>50MB)
    if os.path.getsize(filepath) > 50 * 1024 * 1024:
        return True, "Large executable"

    # Hash check
    if file_hash(filepath) in signatures["hashes"]:
        return True, "Known malware hash"

    # Keyword scan inside scripts
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            for keyword in signatures["keywords"]:
                if keyword in content:
                    return True, f"Suspicious keyword: {keyword}"
    except:
        pass

    return False, ""

def scan_directory(path, quarantine=True):
    report = {
        "total_files": 0,
        "malicious_files": 0,
        "details": []
    }

    for root, _, files in os.walk(path):
        for file in files:
            filepath = os.path.join(root, file)
            report["total_files"] += 1

            malicious, reason = is_suspicious(filepath)
            if malicious:
                report["malicious_files"] += 1
                action = "Quarantined" if quarantine else "Deleted"

                if quarantine:
                    shutil.move(filepath, os.path.join(quarantine_dir, file))
                else:
                    os.remove(filepath)

                report["details"].append({
                    "file": filepath,
                    "reason": reason,
                    "action": action
                })

    # Save report
    report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join(report_dir, report_name), "w") as f:
        json.dump(report, f, indent=4)

    return report

if __name__ == "__main__":
    folder_to_scan = input("Enter folder path to scan: ")
    result = scan_directory(folder_to_scan, quarantine=True)
    print(json.dumps(result, indent=4))
