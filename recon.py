#!/usr/bin/env python3

import socket
import subprocess
import sys
import struct
import os
from datetime import datetime

# ─────────────────────────────────────────
# COULEURS TERMINAL
# ─────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    ROUGE  = "\033[91m"
    VERT   = "\033[92m"
    JAUNE  = "\033[93m"
    BLEU   = "\033[94m"
    CYAN   = "\033[96m"
    GRAS   = "\033[1m"

def info(msg):    print(f"{C.BLEU}[*]{C.RESET} {msg}")
def succes(msg):  print(f"{C.VERT}[+]{C.RESET} {msg}")
def erreur(msg):  print(f"{C.ROUGE}[-]{C.RESET} {msg}")
def warn(msg):    print(f"{C.JAUNE}[!]{C.RESET} {msg}")


# ─────────────────────────────────────────
# 1. PING SWEEP
# ─────────────────────────────────────────
def ping_sweep(subnet):
    info(f"Ping sweep sur {subnet}.0/24 ...")
    actifs = []
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            succes(f"Hôte actif : {ip}")
            actifs.append(ip)
    info(f"{len(actifs)} hôte(s) actif(s) trouvé(s).")
    return actifs


# ─────────────────────────────────────────
# 2. ARP SCAN
# ─────────────────────────────────────────
def arp_scan(subnet):
    info(f"ARP scan sur {subnet}.0/24 ...")
    actifs = []

    # Vérifie si arp-scan est installé
    check = subprocess.run(["which", "arp-scan"], stdout=subprocess.DEVNULL)
    if check.returncode != 0:
        warn("arp-scan non installé. Installe-le avec : sudo apt install arp-scan")
        return actifs

    result = subprocess.run(
        ["sudo", "arp-scan", f"{subnet}.0/24"],
        capture_output=True, text=True
    )
    for ligne in result.stdout.splitlines():
        parties = ligne.split()
        # Une ligne ARP valide ressemble à : 192.168.1.1   aa:bb:cc:dd:ee:ff   Fabricant
        if len(parties) >= 2 and parties[0].count('.') == 3:
            try:
                socket.inet_aton(parties[0])  # Vérifie que c'est une IP valide
                succes(f"IP: {parties[0]}  |  MAC: {parties[1]}  |  Fabricant: {' '.join(parties[2:]) if len(parties) > 2 else 'Inconnu'}")
                actifs.append(parties[0])
            except socket.error:
                pass

    info(f"{len(actifs)} hôte(s) détecté(s) via ARP.")
    return actifs


# ─────────────────────────────────────────
# 3. PORT SCANNER + DÉTECTION DE SERVICE
# ─────────────────────────────────────────

# Dictionnaire des services courants
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL"
}

def detecter_service(port):
    """Retourne le nom du service associé au port."""
    try:
        return socket.getservbyport(port)
    except:
        return SERVICES.get(port, "Inconnu")

def port_scan(cible, ports):
    info(f"Scan de ports sur {cible} ...")
    ouverts = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((cible, port)) == 0:
                service = detecter_service(port)
                succes(f"Port {port}/tcp OUVERT  →  Service : {service}")
                ouverts.append((port, service))
            sock.close()
        except:
            pass
    return ouverts


# ─────────────────────────────────────────
# 4. BANNER GRABBING
# ─────────────────────────────────────────
def banner_grab(cible, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((cible, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banniere = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banniere[:300] if banniere else "Aucune bannière"
    except:
        return "Bannière non disponible"


# ─────────────────────────────────────────
# 5. OS FINGERPRINTING (via TTL + nmap)
# ─────────────────────────────────────────
def deviner_os_ttl(cible):
    """
    Méthode simple : devine l'OS à partir du TTL de la réponse ping.
    TTL ~64  → Linux/Unix/macOS
    TTL ~128 → Windows
    TTL ~255 → Cisco/réseau
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", cible],
            capture_output=True, text=True
        )
        for ligne in result.stdout.splitlines():
            if "ttl=" in ligne.lower():
                ttl = int(ligne.lower().split("ttl=")[1].split()[0])
                if ttl <= 64:
                    return f"Linux / Unix / macOS (TTL={ttl})"
                elif ttl <= 128:
                    return f"Windows (TTL={ttl})"
                else:
                    return f"Équipement réseau Cisco/HP (TTL={ttl})"
    except:
        pass
    return "Inconnu"

def os_fingerprint_nmap(cible):
    """
    Utilise nmap -O pour une détection OS plus précise (nécessite sudo).
    """
    info("Fingerprinting OS via nmap (sudo requis)...")
    check = subprocess.run(["which", "nmap"], stdout=subprocess.DEVNULL)
    if check.returncode != 0:
        warn("nmap non installé. Installe-le avec : sudo apt install nmap")
        return "nmap non disponible"

    result = subprocess.run(
        ["sudo", "nmap", "-O", "--osscan-guess", "-T4", cible],
        capture_output=True, text=True
    )
    for ligne in result.stdout.splitlines():
        if "OS details" in ligne or "Aggressive OS guesses" in ligne:
            return ligne.strip()
    return "Détection nmap non concluante"

def os_fingerprint(cible):
    ttl_result = deviner_os_ttl(cible)
    nmap_result = os_fingerprint_nmap(cible)
    return ttl_result, nmap_result


# ─────────────────────────────────────────
# 6. DNS RESOLUTION
# ─────────────────────────────────────────
def dns_resolution(domaine):
    info(f"Résolution DNS de {domaine} ...")
    resultats = {}

    # Adresse IPv4
    try:
        ipv4 = socket.gethostbyname(domaine)
        succes(f"IPv4 : {ipv4}")
        resultats["IPv4"] = ipv4
    except:
        erreur("IPv4 : Échec de résolution")

    # Infos complètes (hostname, aliases, IPs)
    try:
        info_complete = socket.gethostbyname_ex(domaine)
        if info_complete[1]:
            succes(f"Aliases : {', '.join(info_complete[1])}")
        if len(info_complete[2]) > 1:
            succes(f"Toutes les IPs : {', '.join(info_complete[2])}")
        resultats["toutes_ips"] = info_complete[2]
    except:
        pass

    # Reverse DNS
    try:
        ip = socket.gethostbyname(domaine)
        reverse = socket.gethostbyaddr(ip)[0]
        succes(f"Reverse DNS : {reverse}")
        resultats["reverse"] = reverse
    except:
        erreur("Reverse DNS : Échec")

    return resultats


# ─────────────────────────────────────────
# 7. SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────

# Liste de sous-domaines courants à tester
SOUS_DOMAINES_COMMUNS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "portal", "api", "dev", "staging", "test",
    "blog", "shop", "store", "vpn", "remote", "cdn",
    "static", "media", "images", "docs", "support",
    "help", "forum", "news", "mobile", "app", "login",
    "secure", "dashboard", "panel", "cpanel", "ns1", "ns2"
]

def subdomain_enum(domaine):
    info(f"Énumération des sous-domaines de {domaine} ...")
    trouves = []

    for sub in SOUS_DOMAINES_COMMUNS:
        cible = f"{sub}.{domaine}"
        try:
            ip = socket.gethostbyname(cible)
            succes(f"Trouvé : {cible}  →  {ip}")
            trouves.append((cible, ip))
        except socket.gaierror:
            pass  # Sous-domaine inexistant, on continue

    if not trouves:
        warn("Aucun sous-domaine trouvé.")
    else:
        info(f"{len(trouves)} sous-domaine(s) trouvé(s).")

    return trouves


# ─────────────────────────────────────────
# 8. RAPPORT FINAL
# ─────────────────────────────────────────
def afficher_rapport(cible, ports_ouverts, os_ttl, os_nmap, dns_info=None, subdomains=None):
    sep = "═" * 55
    print(f"\n{C.CYAN}{sep}{C.RESET}")
    print(f"{C.GRAS}  RAPPORT FINAL — {cible}{C.RESET}")
    print(f"  Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{C.CYAN}{sep}{C.RESET}")

    # OS
    print(f"\n{C.JAUNE}[OS FINGERPRINTING]{C.RESET}")
    print(f"  Via TTL   : {os_ttl}")
    print(f"  Via nmap  : {os_nmap}")

    # Ports & Services
    print(f"\n{C.JAUNE}[PORTS & SERVICES]{C.RESET}")
    if ports_ouverts:
        for port, service in ports_ouverts:
            banniere = banner_grab(cible, port)
            print(f"  {C.VERT}{port}/tcp{C.RESET}  |  {service}")
            print(f"    Banner : {banniere[:120]}")
    else:
        print("  Aucun port ouvert détecté.")

    # DNS
    if dns_info:
        print(f"\n{C.JAUNE}[DNS]{C.RESET}")
        for cle, val in dns_info.items():
            print(f"  {cle} : {val}")

    # Sous-domaines
    if subdomains:
        print(f"\n{C.JAUNE}[SOUS-DOMAINES]{C.RESET}")
        for sub, ip in subdomains:
            print(f"  {sub}  →  {ip}")

    print(f"\n{C.CYAN}{sep}{C.RESET}\n")


# ─────────────────────────────────────────
# MENU PRINCIPAL
# ─────────────────────────────────────────
def menu():
    print(f"""
{C.CYAN}{C.GRAS}
  ╔══════════════════════════════════════╗
  ║    Basic Network Recon Tool v2.0     ║
  ║                                      ║
  ╚══════════════════════════════════════╝
{C.RESET}""")
    print("  1. Ping Sweep")
    print("  2. ARP Scan")
    print("  3. Port Scan + Service Detection + OS + Banner")
    print("  4. DNS Resolution")
    print("  5. Subdomain Enumeration")
    print("  6. Recon Complet (tout en un)")
    print("  7. Quitter")
    return input(f"\n{C.GRAS}>> Choix : {C.RESET}").strip()


def main():
    choix = menu()

    if choix == "1":
        subnet = input(">> Sous-réseau (ex: 192.168.1) : ").strip()
        ping_sweep(subnet)

    elif choix == "2":
        subnet = input(">> Sous-réseau (ex: 192.168.1) : ").strip()
        arp_scan(subnet)

    elif choix == "3":
        cible = input(">> IP cible : ").strip()
        print("  1. Top ports courants\n  2. Ports 1-1024\n  3. Personnalisé")
        cp = input(">> : ").strip()
        if cp == "1":
            ports = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080,8443]
        elif cp == "2":
            ports = range(1, 1025)
        else:
            d = int(input(">> Début : "))
            f = int(input(">> Fin : "))
            ports = range(d, f+1)

        ports_ouverts = port_scan(cible, ports)
        os_ttl, os_nmap = os_fingerprint(cible)
        afficher_rapport(cible, ports_ouverts, os_ttl, os_nmap)

    elif choix == "4":
        domaine = input(">> Domaine (ex: example.com) : ").strip()
        dns_resolution(domaine)

    elif choix == "5":
        domaine = input(">> Domaine (ex: example.com) : ").strip()
        subdomain_enum(domaine)

    elif choix == "6":
        print("\n  Mode : IP ou Domaine ?")
        print("  1. IP\n  2. Domaine")
        mode = input(">> : ").strip()

        dns_info = None
        subdomains = None

        if mode == "2":
            domaine = input(">> Domaine : ").strip()
            dns_info = dns_resolution(domaine)
            subdomains = subdomain_enum(domaine)
            cible = dns_info.get("IPv4", domaine)
        else:
            cible = input(">> IP cible : ").strip()

        # Scan complet
        ports = [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080,8443,8443,27017,6379,5432]
        ports_ouverts = port_scan(cible, ports)
        os_ttl, os_nmap = os_fingerprint(cible)
        afficher_rapport(cible, ports_ouverts, os_ttl, os_nmap, dns_info, subdomains)

    elif choix == "7":
        print("Bye!")
        sys.exit(0)

    else:
        erreur("Choix invalide.")

if __name__ == "__main__":
    main()