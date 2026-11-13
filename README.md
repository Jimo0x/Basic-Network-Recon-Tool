# 🔍 Basic Network Recon Tool

> **Projet — Cybersecurity Portfolio**  
> Un outil de reconnaissance réseau en Python, conçu pour cartographier un réseau local et analyser des cibles.

---

## 📋 Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🏓 **Ping Sweep** | Détecte les hôtes actifs sur un sous-réseau |
| 📡 **ARP Scan** | Découvre les machines via le protocole ARP (MAC + fabricant) |
| 🔌 **Port Scanner** | Scanne les ports TCP ouverts d'une cible |
| 🧩 **Service Detection** | Identifie le logiciel qui écoute sur chaque port |
| 🪟 **Banner Grabbing** | Récupère la bannière des services pour obtenir leur version |
| 🖥️ **OS Fingerprinting** | Devine le système d'exploitation via TTL + nmap |
| 🌐 **DNS Resolution** | Résout un domaine en IP, aliases et reverse DNS |
| 🔎 **Subdomain Enumeration** | Trouve les sous-domaines actifs par brute-force wordlist |
| 📊 **Rapport Final** | Affiche un rapport complet et coloré en terminal |

---

## 🖥️ Prérequis

- Python 3.x
- Kali Linux (recommandé) ou toute distribution Linux
- `nmap` et `arp-scan` installés

```bash
sudo apt update
sudo apt install nmap arp-scan -y
```

---

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/Jimo0x/Basic-Network-Recon-Tool.git
cd Basic-Network-Recon-Tool

# Donner les permissions d'exécution
chmod +x recon.py
```

---

## ▶️ Utilisation

```bash
python3 recon.py            # menu interactif
```

### En ligne de commande

```bash
python3 recon.py sweep 192.168.1                # ping sweep du /24 (en parallèle)
python3 recon.py arp 192.168.1.0/24             # scan ARP
python3 recon.py scan 192.168.1.10 -p 22,80,8000-8100 --no-nmap
python3 recon.py dns example.com
python3 recon.py subs example.com
python3 recon.py full example.com               # DNS + sous-domaines + scan
```

Les scans (ping sweep, ports, sous-domaines) tournent en parallèle sur 100 threads :
un ping sweep de /24 passe de plusieurs minutes à quelques secondes.
Les entrées (sous-réseau, ports) sont validées avant toute commande système.

### Menu principal

```
  ╔══════════════════════════════════════╗
  ║    Basic Network Recon Tool v2.0     ║
  ║                                      ║
  ╚══════════════════════════════════════╝

  1. Ping Sweep
  2. ARP Scan
  3. Port Scan + Service Detection + OS + Banner
  4. DNS Resolution
  5. Subdomain Enumeration
  6. Recon Complet (tout en un)
  7. Quitter
```

### Exemples

**Ping Sweep sur un réseau local :**
```
>> Choix : 1
>> Sous-réseau (ex: 192.168.1) : 192.168.1
[*] Ping sweep sur 192.168.1.0/24 ...
[+] Hôte actif : 192.168.1.1
[+] Hôte actif : 192.168.1.42
```

**Scan de ports avec détection de services :**
```
>> Choix : 3
>> IP cible : 192.168.1.1
[+] Port 22/tcp OUVERT  →  Service : SSH
[+] Port 80/tcp OUVERT  →  Service : HTTP
[+] Port 443/tcp OUVERT →  Service : HTTPS
```

**Résolution DNS + sous-domaines :**
```
>> Choix : 6
>> Mode : 2 (Domaine)
>> Domaine : example.com
[+] IPv4 : 93.184.216.34
[+] Trouvé : www.example.com → 93.184.216.34
[+] Trouvé : mail.example.com → 93.184.216.35
```

---

## 📁 Structure du projet

```
network-recon-tool/
│
├── recon.py          # Script principal (bibliothèque standard uniquement)
├── tests/            # Tests (pytest)
└── README.md         # Documentation
```

---

## ⚙️ Détail des modules

### 1. Ping Sweep
Envoie un ping (`ICMP`) à chaque IP du sous-réseau (`x.x.x.1` → `x.x.x.254`) et liste les hôtes qui répondent.

### 2. ARP Scan
Utilise `arp-scan` pour découvrir les machines sur le réseau local avec leur adresse MAC et le fabricant de leur carte réseau.

### 3. Port Scanner
Tente une connexion TCP sur chaque port de la liste. Si la connexion réussit, le port est marqué comme ouvert.

### 4. Service Detection
Identifie le service associé à chaque port via `socket.getservbyport()` et un dictionnaire interne des ports courants.

### 5. Banner Grabbing
Se connecte au service et envoie une requête HTTP pour récupérer la bannière (version du serveur, stack technique).

### 6. OS Fingerprinting
- **TTL** : Analyse la valeur TTL de la réponse ping (`≤64` → Linux, `≤128` → Windows, `>128` → équipement réseau)
- **nmap** : Lance `nmap -O` pour une détection plus précise (nécessite `sudo`)

### 7. DNS Resolution
Résout un nom de domaine en IPv4, liste les aliases et effectue un reverse DNS.

### 8. Subdomain Enumeration
Teste une wordlist de 35+ sous-domaines courants (`www`, `mail`, `api`, `admin`, etc.) et retourne ceux qui résolvent.

---

## ⚠️ Avertissement légal

> Ce projet est développé à des fins **éducatives uniquement**.  
> Scanner un réseau ou un système **sans autorisation explicite** est **illégal** dans la plupart des pays.  
> Utilise cet outil **uniquement** sur ton propre réseau ou dans un environnement de test autorisé (lab, VM, CTF).  
> L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---


## 👤 Auteur

**Jimo0x**  
[![GitHub](https://img.shields.io/badge/GitHub-000?style=flat&logo=github)](https://github.com/Jimo0x)

---

## 📄 Licence

Ce projet est sous licence [MIT](LICENSE).
