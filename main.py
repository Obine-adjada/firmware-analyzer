import argparse
import logging
import json
import sys
from config import FIRMWARE_PATH, EXTRACTED_DIR
from modules.cred_scanner import scan as scan_creds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(description="Firmware Security Analyzer")
    parser.add_argument("--firmware", default=FIRMWARE_PATH)
    parser.add_argument("--extracted", default=EXTRACTED_DIR)
    parser.add_argument("--scan", choices=["creds", "all"], default="all")
    return parser.parse_args()

def main():
    args = parse_args()
    log.info("=== Firmware Security Analyzer ===")
    log.info(f"Filesystem : {args.extracted}")

    findings = []

    if args.scan in ("creds", "all"):
        findings += scan_creds(args.extracted)

    log.info(f"Total findings : {len(findings)}")
    for f in findings:
        print(f"[{f['severity']}] {f['file']}:{f['line']} → {f['content'][:80]}")

if __name__ == "__main__":
    main()
