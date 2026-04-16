# Analyse de sécurité — TP-Link TL-WR841N V14

**Date :** 2026-04-16  
**Firmware :** TL-WR841Nv14_EU_0.9.1_4.16_up_boot[180319-rel57291].bin  
**SHA256 :** 6ceb216895523d2d5baa18ea8092157290b1ee94024561e42e3d17a1b29c9987  
**Architecture :** MIPS little-endian  

---

## Méthodologie

1. Téléchargement du firmware officiel TP-Link
2. Extraction avec binwalk (`squashfs-root`, kernel LZMA)
3. Analyse statique automatisée — 3 modules : `cred_scanner`, `strings_scan`, `vuln_patterns`
4. Vérification manuelle des findings HIGH

---

## Findings

### [HIGH] Mot de passe root trivial — MD5 sans salt

**Fichier :** `etc/passwd.bak`  
**Contenu :** `admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh`

Le compte `admin` dispose des privilèges root (UID 0) et utilise un hash MD5 sans salt (`$1$$`). Le mot de passe `1234` a été cracké en moins d'une seconde avec john + rockyou.

**Impact :** Accès root complet sur le routeur si SSH ou interface web accessible.  
**Remédiation :** Utiliser bcrypt ou SHA-512 avec salt, forcer le changement de mot de passe au premier démarrage.

---

### [HIGH] Service TDDP exposé (CVE-2020-28347)

**Fichier :** `usr/bin/tddp`  
**Référence :** CVE-2020-28347

Le TP-Link Device Discovery Protocol tourne par défaut. Des vulnérabilités d'exécution de commandes à distance sans authentification ont été documentées sur ce service pour des versions proches.

**Impact :** RCE potentiel sur le réseau local sans authentification.  
**Remédiation :** Désactiver TDDP si non utilisé, filtrer le port UDP 1040.

---

### [MEDIUM] WPS actif — attaque Pixie Dust

**Fichier :** `usr/bin/wscd`

Le daemon WPS est actif par défaut. L'attaque Pixie Dust permet de récupérer le PIN WPS en quelques secondes sur les implémentations vulnérables.

**Remédiation :** Désactiver WPS dans l'interface d'administration.

---

### [MEDIUM] UPnP sans authentification

**Fichier :** `usr/bin/upnpd`

UPnP est actif par défaut et écoute sur le multicast `239.255.255.250:1900`. Permet à n'importe quel appareil du réseau local d'ouvrir des ports sur le routeur sans authentification.

**Remédiation :** Désactiver UPnP si non nécessaire.

---

### [MEDIUM] SSH (Dropbear) actif par défaut

**Fichier :** `usr/bin/dropbear`

Le service SSH tourne par défaut, combiné au mot de passe root trivial, cela constitue un vecteur d'accès direct.

**Remédiation :** Désactiver SSH par défaut, activer uniquement sur demande explicite.

---

## Conclusion

5 findings documentés sur ce firmware 2018. Les vulnérabilités les plus critiques (mot de passe root trivial + TDDP) constituent une chaîne d'attaque réaliste sur le réseau local. L'outil d'analyse automatique développé pour ce projet a permis d'identifier l'ensemble de ces findings en moins d'une seconde d'exécution.
