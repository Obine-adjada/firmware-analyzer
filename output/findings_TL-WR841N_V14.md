# Firmware Security Analysis — TP-Link TL-WR841N V14
**Firmware:** TL-WR841Nv14_EU_0.9.1_4.16_up_boot[180319-rel57291].bin  
**Date d'analyse:** 2026-04-16  
**Analyste:** Obine-adjada  

## Findings

### FINDING-001 — Credentials par défaut hardcodés [CRITICAL]
**Fichier:** /etc/passwd.bak  
**Détail:** Compte admin avec mot de passe "admin", hash MD5 sans salt  
**Hash:** $1$$iC.dUsGpxNNJGeOm1dFio/  
**Cracké en:** <1 seconde (rockyou.txt)  
**Impact:** Accès root complet via SSH ou interface web  
**CVSS estimé:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  

### FINDING-002 — Hash MD5 sans salt [HIGH]
**Fichier:** /etc/passwd.bak  
**Détail:** Algorithme MD5 ($1$) obsolète, champ salt vide  
**Impact:** Crack par dictionnaire instantané, pas de protection rainbow table  
**Référence:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)  

### FINDING-003 — SSH activé par défaut [MEDIUM]
**Binaire:** /usr/bin/dropbear  
**Détail:** Service SSH démarré au boot (rcS), combiné avec FINDING-001 = RCE  
**Impact:** Accès shell root distant sans interaction utilisateur  

### FINDING-004 — TDDP exposé [HIGH]
**Binaire:** /usr/bin/tddp  
**Détail:** TP-Link Device Discovery Protocol, CVE connus sur versions proches  
**Références:** CVE-2020-28347, CVE-2021-27246  
**À vérifier:** Confirmer si cette version est vulnérable  

## Prochaines étapes
- [ ] Analyse statique du binaire tddp (strings, ghidra)
- [ ] Analyse de l'interface web (/web/)
- [ ] Recherche d'autres credentials dans /usr/bin/httpd
