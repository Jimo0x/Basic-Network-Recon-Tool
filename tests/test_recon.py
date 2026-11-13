import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import recon  # noqa: E402


@pytest.mark.parametrize("texte,attendu", [
    ("192.168.1", "192.168.1"),
    ("192.168.1.0", "192.168.1"),
    ("10.0.0.0/24", "10.0.0"),
    (" 172.16.5 ", "172.16.5"),
])
def test_valider_subnet_ok(texte, attendu):
    assert recon.valider_subnet(texte) == attendu


@pytest.mark.parametrize("texte", ["192.168", "300.1.1", "abc", "192.168.1; rm -rf /", ""])
def test_valider_subnet_refuse(texte):
    with pytest.raises(ValueError):
        recon.valider_subnet(texte)


def test_parser_ports():
    assert recon.parser_ports("22, 80,8000-8002,22") == [22, 80, 8000, 8001, 8002]
    assert recon.parser_ports("10-8") == [8, 9, 10]


@pytest.mark.parametrize("texte", ["0", "70000", "a-b", ""])
def test_parser_ports_refuse(texte):
    with pytest.raises(ValueError):
        recon.parser_ports(texte)


def test_commande_ping_selon_os(monkeypatch):
    monkeypatch.setattr(recon.platform, "system", lambda: "Windows")
    assert recon.commande_ping("1.2.3.4") == ["ping", "-n", "1", "-w", "1000", "1.2.3.4"]
    monkeypatch.setattr(recon.platform, "system", lambda: "Linux")
    assert recon.commande_ping("1.2.3.4") == ["ping", "-c", "1", "-W", "1", "1.2.3.4"]


def test_port_scan_trouve_un_port_local_ouvert():
    serveur = socket.socket()
    serveur.bind(("127.0.0.1", 0))
    serveur.listen()
    port = serveur.getsockname()[1]
    stop = threading.Event()

    def accepter():
        serveur.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = serveur.accept(); c.close()
            except OSError:
                pass

    t = threading.Thread(target=accepter, daemon=True); t.start()
    try:
        ouverts = recon.port_scan("127.0.0.1", [port, port + 1 if port < 65535 else port - 1], timeout=0.3)
    finally:
        stop.set(); t.join(1); serveur.close()
    assert [p for p, _ in ouverts] == [port]


def test_cli_ports_invalides_code_2(capsys):
    assert recon.main(["scan", "127.0.0.1", "-p", "99999", "--no-nmap"]) == 2
