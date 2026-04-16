import os
import re
import logging
from config import EXTRACTED_DIR, CRED_PATTERNS, TEXT_EXTENSIONS, TARGET_FILES

log = logging.getLogger(__name__)

def scan(extracted_dir=EXTRACTED_DIR):
    log.info("cred_scanner: démarrage...")
    findings = []
    seen = set()

    for root, dirs, files in os.walk(extracted_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            fpath = os.path.join(root, fname)

            if ext not in TEXT_EXTENSIONS and fname not in TARGET_FILES:
                continue

            # Dédup par inode pour éviter les doublons symlink
            try:
                inode = os.stat(fpath).st_ino
                if inode in seen:
                    continue
                seen.add(inode)
            except OSError:
                continue

            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, 1):
                        for pattern in CRED_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                rel_path = os.path.relpath(fpath, extracted_dir)
                                severity = "HIGH" if re.search(r"\$1\$|\$5\$|\$6\$", line) else "MEDIUM"
                                findings.append({
                                    "file": rel_path,
                                    "line": lineno,
                                    "content": line.strip(),
                                    "severity": severity
                                })
                                break  # une seule fois par ligne
            except (PermissionError, IsADirectoryError):
                continue

    log.info(f"cred_scanner: {len(findings)} finding(s) trouvé(s)")
    return findings
