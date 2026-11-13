#!/usr/bin/env python3

import socket
import subprocess
import sys
import struct
import os
import argparse
import ipaddress
import platform
from concurrent.futures import ThreadPoolExecutor
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
THREADS = 100


def valider_subnet(texte):
    """'192.168.1', '192.168.1.0' ou '192.168.1.0/24' -> '192.168.1'. Lève ValueError sinon."""
    texte = texte.strip().split("/")[0]
    octets = texte.split(".")
    if len(octets) == 4:
        octets = octets[:3]
    if len(octets) != 3:
        raise ValueError(f"sous-réseau invalide : {texte!r} (attendu : 192.168.1)")
    base = ".".join(octets)
    ipaddress.IPv4Address(base + ".0")  # lève ValueError si un octet est hors 0-255
    return base


def parser_ports(texte):
    """'22,80,8000-8010' -> [22, 80, 8000, ..., 8010] (trié, sans doublon)."""
    ports = set()
    for morceau in texte.replace(" ", "").split(","):
        if not morceau:
            continue
        if "-" in morceau:
            debut, fin = (int(x) for x in morceau.split("-", 1))
            if debut > fin:
                debut, fin = fin, debut
            ports.update(range(debut, fin + 1))
        else:
            ports.add(int(morceau))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("les ports doivent être entre 1 et 65535")
    return sorted(ports)


def commande_ping(ip, timeout_s=1):
    """Arguments de ping adaptés au système (Windows utilise -n et -w en ms)."""
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    return ["ping", "-c", "1", "-W", str(timeout_s), ip]


def _ping(ip):
    result = subprocess.run(commande_ping(ip), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ip if result.returncode == 0 else None


def ping_sweep(subnet):
    subnet = valider_subnet(subnet)
    info(f"Ping sweep sur {subnet}.0/24 ({THREADS} threads) ...")
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        actifs = [ip for ip in pool.map(_ping, ips) if ip]
    for ip in actifs:
        succes(f"Hôte actif : {ip}")
    info(f"{len(actifs)} hôte(s) actif(s) trouvé(s).")
    return actifs


# ─────────────────────────────────────────
# 2. ARP SCAN
# ─────────────────────────────────────────
def arp_scan(subnet):
    subnet = valider_subnet(subnet)
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

def _tester_port(cible, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return port if sock.connect_ex((cible, port)) == 0 else None
    except OSError:
        return None


def port_scan(cible, ports, timeout=0.5):
    ports = list(ports)
    info(f"Scan de {len(ports)} port(s) sur {cible} ({THREADS} threads) ...")
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        resultats = pool.map(lambda p: _tester_port(cible, p, timeout), ports)
        ouverts = sorted(p for p in resultats if p)
    liste = []
    for port in ouverts:
        service = detecter_service(port)
        succes(f"Port {port}/tcp OUVERT  →  Service : {service}")
        liste.append((port, service))
    return liste


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
        result = subprocess.run(commande_ping(cible), capture_output=True, text=True)
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

    def resoudre(sub):
        cible = f"{sub}.{domaine}"
        try:
            return cible, socket.gethostbyname(cible)
        except (socket.gaierror, UnicodeError):
            return None  # Sous-domaine inexistant

    with ThreadPoolExecutor(max_workers=20) as pool:
        for res in pool.map(resoudre, SOUS_DOMAINES_COMMUNS):
            if res:
                succes(f"Trouvé : {res[0]}  →  {res[1]}")
                trouves.append(res)

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


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443]
PORTS_COMPLET = TOP_PORTS + [27017, 6379, 5432]


def scan_complet(cible, ports, nmap=True):
    ports_ouverts = port_scan(cible, ports)
    os_ttl = deviner_os_ttl(cible)
    os_nmap = os_fingerprint_nmap(cible) if nmap else "ignoré (--no-nmap)"
    return ports_ouverts, os_ttl, os_nmap


def demander_ports():
    print("  1. Top ports courants\n  2. Ports 1-1024\n  3. Personnalisé (ex: 22,80,8000-8100)")
    cp = input(">> : ").strip()
    if cp == "1":
        return TOP_PORTS
    if cp == "2":
        return range(1, 1025)
    while True:
        try:
            return parser_ports(input(">> Ports : "))
        except ValueError as e:
            erreur(f"Entrée invalide : {e}")


def menu_interactif():
    choix = menu()
    try:
        if choix == "1":
            ping_sweep(input(">> Sous-réseau (ex: 192.168.1) : "))
        elif choix == "2":
            arp_scan(input(">> Sous-réseau (ex: 192.168.1) : "))
        elif choix == "3":
            cible = input(">> IP cible : ").strip()
            ports = demander_ports()
            afficher_rapport(cible, *scan_complet(cible, ports))
        elif choix == "4":
            dns_resolution(input(">> Domaine (ex: example.com) : ").strip())
        elif choix == "5":
            subdomain_enum(input(">> Domaine (ex: example.com) : ").strip())
        elif choix == "6":
            print("\n  Mode : IP ou Domaine ?")
            print("  1. IP\n  2. Domaine")
            mode = input(">> : ").strip()
            dns_info = subdomains = None
            if mode == "2":
                domaine = input(">> Domaine : ").strip()
                dns_info = dns_resolution(domaine)
                subdomains = subdomain_enum(domaine)
                cible = dns_info.get("IPv4", domaine)
            else:
                cible = input(">> IP cible : ").strip()
            afficher_rapport(cible, *scan_complet(cible, PORTS_COMPLET), dns_info, subdomains)
        elif choix == "7":
            print("Bye!")
        else:
            erreur("Choix invalide.")
    except ValueError as e:
        erreur(str(e))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Basic Network Recon Tool — à n'utiliser que sur des réseaux et machines que tu es autorisé à tester.",
        epilog="Sans argument, le menu interactif s'ouvre.",
    )
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("sweep", help="ping sweep d'un /24");  p.add_argument("subnet")
    p = sub.add_parser("arp", help="scan ARP d'un /24");      p.add_argument("subnet")
    p = sub.add_parser("scan", help="scan de ports + OS + bannières")
    p.add_argument("cible")
    p.add_argument("-p", "--ports", default=",".join(map(str, TOP_PORTS)), help="ex: 22,80,8000-8100 (défaut : top ports)")
    p.add_argument("--no-nmap", action="store_true", help="ne pas lancer nmap -O (pas de sudo)")
    p = sub.add_parser("dns", help="résolution DNS");          p.add_argument("domaine")
    p = sub.add_parser("subs", help="énumération de sous-domaines"); p.add_argument("domaine")
    p = sub.add_parser("full", help="DNS + sous-domaines + scan d'un domaine")
    p.add_argument("domaine"); p.add_argument("--no-nmap", action="store_true")
    args = parser.parse_args(argv)

    if not args.cmd:
        menu_interactif()
        return 0
    try:
        if args.cmd == "sweep":
            ping_sweep(args.subnet)
        elif args.cmd == "arp":
            arp_scan(args.subnet)
        elif args.cmd == "scan":
            afficher_rapport(args.cible, *scan_complet(args.cible, parser_ports(args.ports), not args.no_nmap))
        elif args.cmd == "dns":
            dns_resolution(args.domaine)
        elif args.cmd == "subs":
            subdomain_enum(args.domaine)
        elif args.cmd == "full":
            dns_info = dns_resolution(args.domaine)
            subdomains = subdomain_enum(args.domaine)
            cible = dns_info.get("IPv4", args.domaine)
            afficher_rapport(cible, *scan_complet(cible, PORTS_COMPLET, not args.no_nmap), dns_info, subdomains)
    except ValueError as e:
        erreur(str(e))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
