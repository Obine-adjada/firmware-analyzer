# Rapport d'analyse de sécurité — TP-Link TL-WR841N V14

**Analyste :** Audrey Adjada (Obine)
**Date :** 2026-04-16
**Firmware :** TL-WR841Nv14_EU_0.9.1_4.16_up_boot[180319-rel57291].bin
**SHA256 :** 6ceb216895523d2d5baa18ea8092157290b1ee94024561e42e3d17a1b29c9987
**Architecture :** MIPS little-endian / SquashFS 4.0 XZ

---

## 1. Contexte

Le TL-WR841N est un routeur grand public TP-Link vendu à des millions d'exemplaires.
Ce rapport analyse la version firmware EU build 180319 (mars 2018), toujours déployée
sur de nombreux appareils en production. L'objectif est d'identifier les vulnérabilités
exploitables depuis le réseau local sans accès physique au routeur.

---

## 2. Méthodologie

### 2.1 Extraction du firmware

Identification des composants avec binwalk :

    DECIMAL     HEXADECIMAL   DESCRIPTION
    53952       0xD2C0        U-Boot 1.1.3 (Mar 19 2018)
    66560       0x10400       LZMA compressed data (kernel Linux)
    1049088     0x100200      Squashfs filesystem, 611 inodes, xz compression

Extraction du filesystem :

    binwalk -e --run-as=root firmware.bin

Résultat : arborescence Linux complète dans squashfs-root/
(bin, etc, usr, lib, web — 611 fichiers)

### 2.2 Analyse statique automatisée

Pipeline Python développé pour ce projet — 3 modules :

- cred_scanner   : détection de credentials hardcodés dans les fichiers système
- strings_scan   : extraction de chaînes suspectes dans les binaires (IPs, URLs, commandes)
- vuln_patterns  : signatures de vulnérabilités connues et services dangereux

Résultats : 51 findings (4 HIGH, 47 MEDIUM) en moins de 2 secondes d'exécution.

### 2.3 Reverse engineering

Binaire cible : usr/bin/tddp (48K, MIPS 32-bit little-endian, strippé)
Outil : Ghidra 11.1.2

---

## 3. Findings

---

### FINDING 1 — CRITICAL
### RCE via tddp_execCmd : exécution de commandes root sans authentification

**Binaire :** usr/bin/tddp
**Fonction Ghidra :** FUN_004015c0 @ offset 0x00401688
**Référence CVE :** CVE-2020-28347 (famille TDDP)

#### Analyse

Le reverse engineering du binaire tddp révèle une fonction nommée tddp_execCmd
(nom visible dans le printf de debug embarqué dans le binaire) :

    undefined4 FUN_004015c0(char *param_1, ...)
    {
        char acStack_110[256];

        vsprintf(acStack_110, param_1, &local_res4);
        printf("[%s():%d] cmd: %s\r\n", "tddp_execCmd", 0x4a, acStack_110);

        __pid = fork();
        if (__pid == 0) {
            local_120 = "sh";
            local_118 = acStack_110;
            execve("/bin/sh", &local_120, (char **)0x0);
            exit(0x7f);
        }
    }

#### Vulnérabilités identifiées

Vulnérabilité 1 — RCE sans validation :
param_1 est une commande reçue depuis le réseau via le protocole TDDP.
Elle est formatée par vsprintf puis passée directement à execve("/bin/sh")
sans aucune validation ni sanitisation. Tout paquet TDDP peut déclencher
l'exécution d'une commande arbitraire en root.

Vulnérabilité 2 — Stack buffer overflow :
vsprintf écrit dans un buffer fixe de 256 octets (acStack_110) sans aucune
vérification de taille. Un input supérieur à 256 octets provoque un débordement
de pile potentiellement exploitable.

#### Impact

Exécution de commandes arbitraires en root depuis le réseau local,
sans aucune authentification requise.

#### Remédiation

- Remplacer vsprintf par vsnprintf avec limite explicite : vsnprintf(acStack_110, sizeof(acStack_110), param_1, ...)
- Valider et sanitiser toute entrée réseau avant exécution
- Désactiver TDDP si non utilisé, filtrer le port UDP 1040

---

### FINDING 2 — HIGH
### Credentials root hardcodés — hash MD5 sans salt cracké en moins d'une seconde

**Fichier :** etc/passwd.bak
**Hash :** $1$$iC.dUsGpxNNJGeOm1dFio/
**Mot de passe :** 1234
**Algorithme :** MD5 sans salt ($1$$)

#### Analyse

Le fichier passwd.bak est copié vers /var/passwd au démarrage (rcS) :

    cp -p /etc/passwd.bak /var/passwd

Contenu :

    admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh

Trois problèmes cumulés :
- MD5 sans salt : algorithme obsolète depuis 2004, absence de salt = pas de protection
  contre les attaques par table arc-en-ciel
- Mot de passe trivial : "1234" cracké en moins d'une seconde avec john + rockyou
- Privilèges root : UID 0, GID 0 — l'utilisateur admin est root

Commande utilisée :

    john --wordlist=rockyou.txt hash.txt
    → 1234 (admin) — 0:00:00:00

#### Impact

Accès root immédiat via SSH ou interface web d'administration.

#### Remédiation

- Utiliser bcrypt ou SHA-512 avec salt ($6$)
- Forcer le changement de mot de passe au premier démarrage
- Ne jamais stocker de credentials dans le filesystem read-only

---

### FINDING 3 — HIGH
### SSH Dropbear actif par défaut combiné aux credentials triviaux

**Fichier :** usr/bin/dropbear

#### Analyse

Le service SSH Dropbear est démarré automatiquement au boot via rcS.
Combiné au compte admin:1234 avec UID 0, cela constitue un accès root
direct sans aucune barrière supplémentaire.

    Connexion : ssh admin@192.168.0.1
    Mot de passe : 1234
    Résultat : shell root immédiat

#### Impact

Accès root SSH immédiat pour tout attaquant sur le réseau local.

#### Remédiation

- Désactiver SSH par défaut
- Activer uniquement sur demande explicite via l'interface web
- Implémenter une authentification par clé publique

---

### FINDING 4 — MEDIUM
### WPS actif — attaque Pixie Dust (SoC MediaTek MT7628)

**Fichier :** usr/bin/wscd

#### Analyse

Le daemon WPS est actif par défaut. Ce routeur utilise un SoC MediaTek MT7628,
dont les implémentations WPS sont connues pour être vulnérables à l'attaque
Pixie Dust — récupération du PIN WPS en quelques secondes via une faille
dans le générateur de nombres aléatoires.

#### Impact

Accès WiFi complet sans connaître le mot de passe WPA.

#### Remédiation

Désactiver WPS dans l'interface d'administration.

---

### FINDING 5 — MEDIUM
### UPnP sans authentification — ouverture de ports arbitraire

**Fichier :** usr/bin/upnpd
**Adresse multicast :** 239.255.255.250:1900

#### Analyse

UPnP est actif par défaut. Tout appareil du réseau local peut envoyer
des requêtes SOAP au daemon upnpd pour ouvrir des ports sur le routeur,
sans aucune authentification. Vecteur d'attaque classique pour exposer
des services internes vers internet.

#### Remédiation

Désactiver UPnP si non nécessaire.

---

## 4. Chaîne d'attaque complète

Scénario : attaquant sur le réseau local (WiFi voisin ou appareil compromis)

    [1] Scan réseau
        nmap 192.168.0.1
        → ports ouverts : 22 (SSH), 80 (HTTP), UDP 1040 (TDDP)

    [2a] Vecteur SSH
        ssh admin@192.168.0.1
        password: 1234
        → shell root immédiat

    [2b] Vecteur TDDP (sans credentials)
        Envoi paquet TDDP malformé → tddp_execCmd → execve(/bin/sh)
        → shell root sans authentification

    [3] Post-exploitation
        - Lecture de tous les mots de passe WiFi stockés
        - Pivot vers tous les appareils du réseau local
        - Installation de backdoor persistante
        - Redirection DNS pour attaques man-in-the-middle

Temps estimé depuis le réseau local : moins de 2 minutes.

---

## 5. Conclusion

Ce firmware présente une surface d'attaque critique. La vulnérabilité tddp_execCmd,
confirmée par reverse engineering Ghidra, permet une RCE root sans authentification
depuis le réseau local. Combinée aux credentials triviaux et au SSH actif par défaut,
elle constitue une chaîne d'attaque complète en moins de 2 minutes.

L'ensemble de ces findings a été identifié avec des outils open source uniquement :
binwalk, john the ripper, Ghidra. Le pipeline d'analyse automatisé développé pour
ce projet (3 modules Python, 51 findings détectés en moins de 2 secondes) est
réutilisable sur n'importe quel firmware SquashFS.

---

## 6. Références

- CVE-2020-28347 : TP-Link TDDP command injection
- CVE-2021-27246 : TP-Link TDDP stack overflow
- Ghidra NSA : https://ghidra-sre.org
- binwalk : https://github.com/ReFirmLabs/binwalk
