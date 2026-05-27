For a MacBook, the answer is **hybrid**: use **Objective-See's free macOS security suite** for the heavy lifting, then wrap it with a **custom Python evidence-collection script** for forensic documentation. This gives you both detection depth and chain-of-custody rigor.

---

## Recommended Stack

### 1. Third-Party Tools (Primary Detection)

| Tool | Purpose | Why It Matters for Your Use Case |
|------|---------|----------------------------------|
| **KnockKnock** | Persistence enumerator | Scans LaunchAgents, LaunchDaemons, browser extensions, login items, cron jobs, and kernel extensions—the exact hiding spots stalkerware/RATs use |
| **Netiquette** | Network monitor | Maps live connections and listening ports; catches C2 beaconing |
| **ReiKey** | Keylogger detector | Scans for keyboard event taps (IOKit hooks) used by commercial stalkerware like FlexiSPY |
| **TaskExplorer** | Process inspector | Shows code signatures, VT hashes, and parent-child process trees |
| **BlockBlock** | Real-time persistence monitor | Alerts when something installs persistence (run this after cleanup to prevent reinfection) |
| **KextViewr** | Kernel extension viewer | Flags legacy kexts or unsigned drivers |

**Source:** [Objective-See](https://objective-see.org/tools.html) — all free, terminal-friendly, and built by Patrick Wardle (former NSA, macOS malware specialist).

**Commercial AV supplement:** If you want signature-based coverage for known commercial stalkerware families, add **Malwarebytes for Mac** (100% stalkerware detection in AV-Comparatives 2025) or **ESET Cyber Security** (94%). Run these *after* KnockKnock so you don't destroy behavioral evidence before documenting it.

### 2. Custom Python Script (Forensic Documentation)

A Python script won't beat a kernel-level rootkit, but it excels at **evidence preservation** and **baseline deviation detection**. Build it to:

1. **Hash and inventory** all persistence artifacts before removal
2. **Parse plists** (LaunchAgents/Daemons) to extract execution paths and timestamps
3. **Cross-reference** running processes against known-good baselines
4. **Generate a timestamped JSON/CSV report** for legal admissibility

---

## Python Script Architecture

```python
#!/usr/bin/env python3
"""
macOS Spyware/Stalkerware Forensic Enumerator
Generates chain-of-custody documentation for persistence artifacts.
"""

import os
import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
import plistlib

# --- Configuration ---
OUTPUT_DIR = Path("~/Desktop/mac_forensics").expanduser()
TIMESTAMP = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
CASE_ID = f"MAC_SCAN_{TIMESTAMP}"

# Persistence paths to inventory
PERSISTENCE_PATHS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchDaemons",
    "~/Library/LaunchDaemons",  # non-standard but used by malware
    "~/Library/Preferences/com.apple.loginitems.plist",
    "/private/var/at/tabs",  # cron
    "/etc/periodic",
    "~/Library/Containers",  # sandboxed app persistence
]

# Browser extension paths
BROWSER_PATHS = [
    "~/Library/Application Support/Google/Chrome/Default/Extensions",
    "~/Library/Application Support/Firefox/Profiles",
    "~/Library/Safari/Extensions",
]

# TCC (Privacy) database - requires Full Disk Access
TCC_DB = "~/Library/Application Support/com.apple.TCC/TCC.db"

def hash_file(filepath):
    """SHA-256 hash for evidence integrity."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        return f"ERROR: {e}"

def enumerate_launch_plists(path):
    """Parse LaunchAgent/Daemon plists for IOCs."""
    findings = []
    p = Path(path).expanduser()
    if not p.exists():
        return findings
    
    for plist_file in p.glob("*.plist"):
        try:
            with open(plist_file, "rb") as f:
                data = plistlib.load(f)
            
            findings.append({
                "file": str(plist_file),
                "sha256": hash_file(plist_file),
                "label": data.get("Label"),
                "program": data.get("Program"),
                "program_arguments": data.get("ProgramArguments"),
                "run_at_load": data.get("RunAtLoad"),
                "keep_alive": data.get("KeepAlive"),
                "start_interval": data.get("StartInterval"),
                "modified": datetime.fromtimestamp(plist_file.stat().st_mtime).isoformat()
            })
        except Exception as e:
            findings.append({"file": str(plist_file), "error": str(e)})
    return findings

def check_tcc_abuse():
    """Check for apps with dangerous TCC permissions (camera, mic, accessibility)."""
    # Requires sqlite3 and Full Disk Access for terminal
    results = []
    db_path = Path(TCC_DB).expanduser()
    if not db_path.exists():
        return [{"error": "TCC.db not accessible. Grant Full Disk Access to Terminal."}]
    
    try:
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT service, client, auth_value, last_modified 
            FROM access 
            WHERE service IN ('kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceAccessibility')
        """)
        for row in cursor.fetchall():
            results.append({
                "service": row[0],
                "client": row[1],
                "authorized": row[2],  # 2 = allowed
                "last_modified": row[3]
            })
    except Exception as e:
        results.append({"error": str(e)})
    return results

def check_login_items():
    """Enumerate user login items."""
    try:
        result = subprocess.run(
            ["osascript", "-e", 'tell application "System Events" to get the name of every login item'],
            capture_output=True, text=True
        )
        return result.stdout.strip().split(", ") if result.returncode == 0 else []
    except Exception as e:
        return [str(e)]

def check_network_connections():
    """Active network connections (C2 detection)."""
    try:
        result = subprocess.run(["lsof", "-i", "-P", "-n"], capture_output=True, text=True)
        lines = result.stdout.strip().split("\n")[1:]  # skip header
        connections = []
        for line in lines[:100]:  # limit output
            parts = line.split()
            if len(parts) >= 9:
                connections.append({
                    "process": parts[0],
                    "pid": parts[1],
                    "user": parts[2],
                    "protocol": parts[7],
                    "connection": parts[8]
                })
        return connections
    except Exception as e:
        return [{"error": str(e)}]

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "case_id": CASE_ID,
        "timestamp_utc": datetime.utcnow().isoformat(),
        "hostname": subprocess.getoutput("hostname"),
        "username": os.getlogin(),
        "system_profiler": subprocess.getoutput("system_profiler SPHardwareDataType | grep 'Model Identifier\\|Serial Number'"),
        "findings": {}
    }
    
    # 1. Persistence enumeration
    report["findings"]["launch_persistence"] = {}
    for path in PERSISTENCE_PATHS:
        report["findings"]["launch_persistence"][path] = enumerate_launch_plists(path)
    
    # 2. Browser extensions
    report["findings"]["browser_extensions"] = {}
    for path in BROWSER_PATHS:
        p = Path(path).expanduser()
        if p.exists():
            report["findings"]["browser_extensions"][path] = [
                {"name": x.name, "modified": datetime.fromtimestamp(x.stat().st_mtime).isoformat()}
                for x in p.rglob("*") if x.is_dir() and x.name != "."
            ]
    
    # 3. TCC permissions
    report["findings"]["tcc_permissions"] = check_tcc_abuse()
    
    # 4. Login items
    report["findings"]["login_items"] = check_login_items()
    
    # 5. Network connections
    report["findings"]["network_connections"] = check_network_connections()
    
    # Write report
    output_file = OUTPUT_DIR / f"{CASE_ID}_report.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    
    # Generate CSV summary for quick review
    csv_file = OUTPUT_DIR / f"{CASE_ID}_persistence_summary.csv"
    with open(csv_file, "w") as f:
        f.write("type,path,label,program,sha256,modified\n")
        for path, items in report["findings"]["launch_persistence"].items():
            for item in items:
                if "label" in item:
                    f.write(f"launch_item,\"{path}\",\"{item.get('label','')}\",\"{item.get('program','')}\",\"{item.get('sha256','')}\",\"{item.get('modified','')}\"\n")
    
    print(f"[+] Forensic report saved: {output_file}")
    print(f"[+] CSV summary saved: {csv_file}")
    print(f"[!] Next steps: Run KnockKnock manually to verify findings, then hash suspicious binaries.")

if __name__ == "__main__":
    main()
```

---

## Execution Workflow

**Phase 1: Evidence Preservation (Do this first)**
```bash
# 1. Grant Full Disk Access to Terminal/iTerm
# System Settings → Privacy & Security → Full Disk Access → Add Terminal

# 2. Run the Python enumerator
python3 macos_forensic_scan.py

# 3. Run Objective-See suite
# Download from https://objective-see.org/tools.html
./KnockKnock.app/Contents/MacOS/KnockKnock -scan > knockknock_output.txt
./Netiquette.app/Contents/MacOS/Netiquette > netiquette_output.txt
./ReiKey.app/Contents/MacOS/ReiKey -scan > reikey_output.txt
```

**Phase 2: Analysis**
- Cross-reference the Python JSON output with KnockKnock's findings
- Look for **unsigned binaries** in LaunchAgents, **browser extensions** you didn't install, and **keyboard event taps** (ReiKey)
- Check network connections for beaconing to known-bad IPs (cross-reference with AbuseIPDB or VirusTotal)

**Phase 3: Remediation**
- If commercial stalkerware is found: **document screenshots first**, then remove persistence plists and reboot
- If a RAT is suspected: **disconnect from network**, boot to Safe Mode, and re-run scans
- If government-grade is suspected: **do not remediate yourself**—contact Citizen Lab or Amnesty Tech for forensic preservation

---

## What This Won't Catch

| Threat Level | Limitation | Mitigation |
|--------------|-----------|------------|
| **Kernel rootkit** | Python can't inspect kernel memory reliably | Use `kextstat` + KextViewr; suspect if SIP is disabled |
| **Hardware implant** | No software detection possible | Physical inspection of USB-C/Thunderbolt devices |
| **Memory-resident only** | No memory dump capability | Use `vmmap` or commercial forensic suite (BlackBag/Cellebrite) |
| **Legitimate app abuse** (e.g., TeamViewer, Chrome Remote Desktop) | These are valid programs used maliciously | Check TCC permissions and unauthorized login items |

---

## Bottom Line

**For your operational context:** Start with **KnockKnock + ReiKey + Netiquette** (free, immediate, terminal-friendly). Use the **Python script above** as your evidence-collection wrapper to generate timestamped, hashed reports suitable for your SCADMS/AVHERI documentation standards. Add **Malwarebytes** only if you need signature confirmation of known stalkerware families.

If this is for a live case and physical safety is a factor, **document before you delete**.
