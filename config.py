import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data/firmwares")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

FIRMWARE_NAME = "TL-WR841Nv14_EU_0.9.1_4.16_up_boot[180319-rel57291].bin"
FIRMWARE_PATH = os.path.join(DATA_DIR, FIRMWARE_NAME)
EXTRACTED_DIR = os.path.join(DATA_DIR, f"_{FIRMWARE_NAME}.extracted/squashfs-root")

# Patterns ciblés — uniquement credentials réels, pas du JS web
CRED_PATTERNS = [
    r"^\S+:\$1\$[^\s:]+",        # hash MD5 dans passwd
    r"^\S+:\$5\$[^\s:]+",        # hash SHA-256
    r"^\S+:\$6\$[^\s:]+",        # hash SHA-512
    r"password\s*=\s*['\"]?\w+", # password=valeur dans configs
    r"passwd\s*=\s*['\"]?\w+",
]

TEXT_EXTENSIONS = [
    ".conf", ".cfg", ".sh", ".ini", ".bak", ".default"
]

# Fichiers spécifiques toujours scannés
TARGET_FILES = {"passwd", "passwd.bak", "shadow"}
