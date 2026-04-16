# Firmware Security Analyzer

Outil d'analyse statique de firmwares IoT.

## Premier firmware analysé
- TP-Link TL-WR841N V14 (EU) — build 180319
- Architecture : MIPS little-endian
- Filesystem : SquashFS 4.0 / XZ

## Findings initiaux
- [CRIT] Mot de passe root hardcodé cracké en <1s (MD5 sans salt, `admin:1234`)
- [MED] Service SSH (dropbear) actif par défaut
- [MED] Service TDDP exposé (CVE connus sur versions proches)
