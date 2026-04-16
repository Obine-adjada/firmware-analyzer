import json
import os
import hashlib
from datetime import datetime
from config import OUTPUT_DIR, FIRMWARE_NAME

def generer(findings, firmware_path=None):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Hash du firmware pour l'identifier de façon unique
    sha256 = ""
    if firmware_path and os.path.isfile(firmware_path):
        h = hashlib.sha256()
        with open(firmware_path, "rb") as f:
            for bloc in iter(lambda: f.read(8192), b""):
                h.update(bloc)
        sha256 = h.hexdigest()

    rapport = {
        "firmware": FIRMWARE_NAME,
        "sha256": sha256,
        "date_analyse": datetime.now().isoformat(),
        "vendor": "TP-Link",
        "modele": "TL-WR841N",
        "version_hw": "V14",
        "build": "180319",
        "architecture": "MIPS little-endian",
        "resume": {
            "total": len(findings),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings
    }

    outpath = os.path.join(OUTPUT_DIR, "report.json")
    with open(outpath, "w") as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False)

    return outpath
