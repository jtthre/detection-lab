#!/usr/bin/env python3
"""
generer-cas-lumma.py — fabrique un petit pcap SYNTHÉTIQUE pour tester les règles 1000001/1000002.

Aucun trafic réel : des requêtes HTTP écrites à la main, entre adresses de documentation
(10.9.9.10 -> 203.0.113.50). Huit cas :
    4 positifs  : GET et POST /api/set_agent pour « Chrome » puis « Edge », dont deux vers un
                  autre nom d'hôte (la règle ne doit pas dépendre du domaine) ;
    4 négatifs  : /favicon.ico, /api/set_agent mal formé, un autre chemin avec act=log, et une
                  recherche dont la chaîne de requête contient « api/set_agent&act=log ».
Attendu : exactement 4 alertes (2 × 1000001, 2 × 1000002), aucune sur les négatifs.

Usage :
    python3 generer-cas-lumma.py /tmp/cas-lumma.pcap
    suricata -r /tmp/cas-lumma.pcap -k none -S ../local.rules -l /tmp/test-regles
    cat /tmp/test-regles/fast.log

Le pcap produit reste hors du dépôt (*.pcap est ignoré) : on versionne le générateur.
Nécessite scapy (sudo apt install python3-scapy).
"""
import sys
from scapy.all import IP, TCP, Raw, wrpcap
pk=[]; t=[1800000000.0]
def flow(sport, req, resp=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"):
    c,s="10.9.9.10","203.0.113.50"
    cs, ss = 1000, 5000
    def add(p): t[0]+=0.01; p.time=t[0]; pk.append(p)
    add(IP(src=c,dst=s)/TCP(sport=sport,dport=80,flags="S",seq=cs))
    add(IP(src=s,dst=c)/TCP(sport=80,dport=sport,flags="SA",seq=ss,ack=cs+1))
    add(IP(src=c,dst=s)/TCP(sport=sport,dport=80,flags="A",seq=cs+1,ack=ss+1))
    add(IP(src=c,dst=s)/TCP(sport=sport,dport=80,flags="PA",seq=cs+1,ack=ss+1)/Raw(req))
    add(IP(src=s,dst=c)/TCP(sport=80,dport=sport,flags="A",seq=ss+1,ack=cs+1+len(req)))
    add(IP(src=s,dst=c)/TCP(sport=80,dport=sport,flags="PA",seq=ss+1,ack=cs+1+len(req))/Raw(resp))
    add(IP(src=c,dst=s)/TCP(sport=sport,dport=80,flags="A",seq=cs+1+len(req),ack=ss+1+len(resp)))
ID="3BF67EC05320C5729578BE4C0ADF174C"; TOK="0123456789abcdef0123456789abcdef01234567"
def req(m,u,body=b"",host=b"exemple.test"):
    h=m.encode()+b" "+u.encode()+b" HTTP/1.1\r\nHost: "+host+b"\r\nUser-Agent: Mozilla/5.0\r\n"
    if body: h+=b"Content-Length: "+str(len(body)).encode()+b"\r\n"
    return h+b"\r\n"+body
cas = [  # (attendu, requete)
 ("1000001", req("GET", f"/api/set_agent?id={ID}&token={TOK}&description=&agent=Chrome")),
 ("1000002", req("POST",f"/api/set_agent?id={ID}&token={TOK}&description=&agent=Chrome&act=log", b"x"*500)),
 ("1000001", req("GET", f"/api/set_agent?id={ID}&token={TOK}&description=&agent=Edge", host=b"autre-domaine.example")),
 ("1000002", req("POST",f"/api/set_agent?id={ID}&token={TOK}&description=&agent=Edge&act=log", b"y"*500, host=b"autre-domaine.example")),
 ("-", req("GET", "/favicon.ico")),
 ("-", req("GET", "/api/set_agent?id=abc&token=1&agent=x")),
 ("-", req("POST","/api/upload?act=log", b"z")),
 ("-", req("GET", "/search?q=api/set_agent&act=log")),
]
for i,(a,r) in enumerate(cas): flow(40000+i, r)
sortie = sys.argv[1] if len(sys.argv) > 1 else "cas-lumma.pcap"
wrpcap(sortie, pk)
print(f"{len(cas)} flux écrits dans {sortie} (4 positifs, 4 négatifs)")
