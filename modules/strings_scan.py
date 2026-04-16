import os
import re
import subprocess
import logging
from config import EXTRACTED_DIR

log = logging.getLogger(__name__)

# Ce qu'on cherche dans les binaires
PATTERNS = {
    "ip_hardcodee": r"\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255)(\d{1,3}\.){3}\d{1,3}\b",
    "url_http":     r"https?://[^\s\"'<>]+",
    "commande_shell": r"(system|popen|exec|eval)\s*\(['\"]([^'\"]{5,})['\"]",
    "chemin_suspect": r"/(etc/passwd|etc/shadow|tmp/[^\s]+|var/run/[^\s]+)",
}

# Binaires ciblés — les plus intéressants
CIBLES = ["httpd", "tddp", "cos", "wscd", "upnpd"]

def extraire_strings(fpath):
    try:
        result = subprocess.run(
            ["strings", "-n", "8", fpath],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

def scan(extracted_dir=EXTRACTED_DIR):
    log.info("strings_scan: démarrage...")
    findings = []

    bin_dirs = [
        os.path.join(extracted_dir, "usr/bin"),
        os.path.join(extracted_dir, "usr/sbin"),
        os.path.join(extracted_dir, "bin"),
        os.path.join(extracted_dir, "sbin"),
    ]

    for bin_dir in bin_dirs:
        if not os.path.isdir(bin_dir):
            continue
        for fname in os.listdir(bin_dir):
            if fname not in CIBLES:
                continue
            fpath = os.path.join(bin_dir, fname)
            chaines = extraire_strings(fpath)

            for chaine in chaines:
                for nom_pattern, pattern in PATTERNS.items():
                    match = re.search(pattern, chaine)
                    if match:
                        findings.append({
                            "file": f"usr/bin/{fname}",
                            "content": chaine.strip(),
                            "type": nom_pattern,
                            "severity": "HIGH" if nom_pattern == "commande_shell" else "MEDIUM"
                        })
                        break

    log.info(f"strings_scan: {len(findings)} finding(s) trouvé(s)")
    return findings
