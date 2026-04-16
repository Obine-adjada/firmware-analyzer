import os
import re
import subprocess
import logging
from config import EXTRACTED_DIR

log = logging.getLogger(__name__)

# Signatures de vulnérabilités documentées publiquement
SIGNATURES = [
    {
        "id": "TDDP-001",
        "description": "Service TDDP présent — vulnérabilités connues (CVE-2020-28347)",
        "cible": "usr/bin/tddp",
        "type": "presence",
        "severity": "HIGH",
    },
    {
        "id": "WPS-001",
        "description": "Service WPS actif (wscd) — vulnérable Pixie Dust",
        "cible": "usr/bin/wscd",
        "type": "presence",
        "severity": "MEDIUM",
    },
    {
        "id": "UPNP-001",
        "description": "UPnP daemon actif sans authentification",
        "cible": "usr/bin/upnpd",
        "type": "presence",
        "severity": "MEDIUM",
    },
    {
        "id": "SSH-001",
        "description": "Dropbear SSH actif par défaut",
        "cible": "usr/bin/dropbear",
        "type": "presence",
        "severity": "MEDIUM",
    },
    {
        "id": "TELNET-001",
        "description": "Telnet activé dans la config réseau",
        "cible": "etc/inetd.conf",
        "type": "contenu",
        "pattern": r"telnet",
        "severity": "HIGH",
    },
    {
        "id": "MD5-001",
        "description": "Hash MD5 sans salt dans passwd — cassable en <1s",
        "cible": "etc/passwd.bak",
        "type": "contenu",
        "pattern": r":\$1\$\$",
        "severity": "HIGH",
    },
    {
        "id": "SHELL-001",
        "description": "Shell root assigné au compte admin",
        "cible": "etc/passwd.bak",
        "type": "contenu",
        "pattern": r"admin:.+:/bin/sh",
        "severity": "HIGH",
    },
]

def scan(extracted_dir=EXTRACTED_DIR):
    log.info("vuln_patterns: démarrage...")
    findings = []

    for sig in SIGNATURES:
        fpath = os.path.join(extracted_dir, sig["cible"])

        if sig["type"] == "presence":
            if os.path.isfile(fpath):
                findings.append({
                    "id": sig["id"],
                    "file": sig["cible"],
                    "description": sig["description"],
                    "severity": sig["severity"],
                    "content": f"binaire présent : {sig['cible']}"
                })

        elif sig["type"] == "contenu":
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        if re.search(sig["pattern"], line, re.IGNORECASE):
                            findings.append({
                                "id": sig["id"],
                                "file": sig["cible"],
                                "line": lineno,
                                "description": sig["description"],
                                "severity": sig["severity"],
                                "content": line.strip()
                            })
                            break
            except (PermissionError, IsADirectoryError):
                continue

    log.info(f"vuln_patterns: {len(findings)} finding(s) trouvé(s)")
    return findings
