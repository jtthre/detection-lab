#!/usr/bin/env python3
"""
generer-cas-port443.py — pcap SYNTHÉTIQUE pour tester la règle 1000003 (port 443 sans protocole).

Quatre flux écrits à la main, entre adresses de documentation (10.9.9.10 -> 203.0.113.60) :
    1. octets aléatoires sur le port 443, pendant ~2 min   -> attendu : 1 alerte (une seule
                                                               pour tout le flux, grâce aux flowbits)
    2. HTTP en clair sur le port 443 (façon NetSupport)    -> attendu : 0 (protocole reconnu : http)
    3. octets aléatoires sur le port 8443                   -> attendu : 0 (la règle vise le 443)
    4. octets aléatoires sur le port 443, moins d'1 s      -> attendu : 0 (rev 2 : flux trop bref)

Usage :
    python3 generer-cas-port443.py /tmp/cas-port443.pcap
    suricata -r /tmp/cas-port443.pcap -k none -S ../local.rules -l /tmp/test-regles
    grep -c 1000003 /tmp/test-regles/fast.log        # attendu : 1

Le pcap produit reste hors du dépôt. Nécessite scapy (sudo apt install python3-scapy).
"""
import random
import sys
from scapy.all import IP, TCP, Raw, wrpcap

paquets = []
horloge = [1800000000.0]


def flux(port_src, port_dst, echanges, pas=0.01):
    c, s = "10.9.9.10", "203.0.113.60"
    cs, ss = 1000, 5000

    def ajouter(p):
        horloge[0] += pas
        p.time = horloge[0]
        paquets.append(p)

    ajouter(IP(src=c, dst=s) / TCP(sport=port_src, dport=port_dst, flags="S", seq=cs))
    ajouter(IP(src=s, dst=c) / TCP(sport=port_dst, dport=port_src, flags="SA", seq=ss, ack=cs + 1))
    cs += 1
    ss += 1
    ajouter(IP(src=c, dst=s) / TCP(sport=port_src, dport=port_dst, flags="A", seq=cs, ack=ss))
    for sens, donnees in echanges:
        if sens == "client":
            ajouter(IP(src=c, dst=s) / TCP(sport=port_src, dport=port_dst, flags="PA", seq=cs, ack=ss) / Raw(donnees))
            cs += len(donnees)
            ajouter(IP(src=s, dst=c) / TCP(sport=port_dst, dport=port_src, flags="A", seq=ss, ack=cs))
        else:
            ajouter(IP(src=s, dst=c) / TCP(sport=port_dst, dport=port_src, flags="PA", seq=ss, ack=cs) / Raw(donnees))
            ss += len(donnees)
            ajouter(IP(src=c, dst=s) / TCP(sport=port_src, dport=port_dst, flags="A", seq=cs, ack=ss))


random.seed(3)
aleatoire = lambda n: bytes(random.getrandbits(8) for _ in range(n))

flux(41000, 443, [("client", aleatoire(300)), ("serveur", aleatoire(1200))] * 20, pas=1.0)   # ~2 min
flux(41001, 443, [("client", b"POST /fakeurl.htm HTTP/1.1\r\nHost: 203.0.113.60\r\nContent-Length: 4\r\n\r\nabcd"),
                  ("serveur", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")])
flux(41002, 8443, [("client", aleatoire(300)), ("serveur", aleatoire(1200))] * 5)
flux(41003, 443, [("client", aleatoire(300)), ("serveur", aleatoire(1200))] * 5)       # < 1 s

sortie = sys.argv[1] if len(sys.argv) > 1 else "cas-port443.pcap"
wrpcap(sortie, paquets)
print(f"4 flux écrits dans {sortie} (attendu : 1 alerte 1000003)")
