#!/usr/bin/env python3
"""
balisement.py — repère les conversations trop régulières dans un journal de Zeek.

Un implant C2 rappelle son serveur à intervalle fixe, avec une requête et une réponse
de taille presque constante. Ni le chiffrement ni le changement de domaine n'effacent
ce rythme. Ce script le mesure.

ENTRÉE
    Un conn.log ou un http.log de Zeek, au format TSV (par défaut) ou JSON (une ligne par
    événement, LogAscii::use_json=T). Le format et le type de journal sont détectés
    automatiquement.

    conn.log  : un événement = une connexion TCP/UDP ; volume = orig_bytes + resp_bytes.
    http.log  : un événement = une requête HTTP ; volume = request_body_len + response_body_len.

    Pourquoi les deux : un implant qui ouvre une connexion par rappel se voit dans conn.log.
    Un implant qui garde UNE connexion ouverte et y enchaîne ses requêtes (keep-alive) n'y
    laisse que quelques lignes, longues : le rythme n'existe plus qu'au niveau des requêtes.
    Constaté sur la capture NetSupport du 2026-02-28 — 264 rappels HTTP vers le C2, portés
    par trop peu de connexions pour être évalués dans conn.log.

REGROUPEMENT
    Les connexions sont regroupées par paire (source, destination, port de destination).
    Une paire n'est évaluée qu'à partir de --min-connexions connexions (20 par défaut) ET
    sur au moins --duree-min secondes d'activité (300 par défaut). En dessous, aucune
    statistique n'est fiable : cinq connexions en une minute paraissent « régulières »
    sans rien dire d'un rythme. Constaté sur la capture Lumma du 2026-01-31 — une paire
    Microsoft de 5 connexions en 74 s sortait à 0,78, au-dessus du vrai C2.

LE SCORE (0 à 1)
    Statistiques robustes uniquement : médiane, écart absolu médian (MAD), asymétrie de
    Bowley. Elles résistent aux valeurs aberrantes et à la gigue qu'un framework C2 ajoute
    exprès pour casser la régularité. C'est la même famille de calcul que RITA.

    Pour une série de valeurs (les écarts entre connexions, ou les tailles) :
        dispersion = 1 - min(1, MAD / médiane)   -> 1 si toutes les valeurs se ressemblent
        symétrie   = 1 - |Bowley|                -> 1 si les valeurs sont centrées sur la médiane
        régularité = 0,7 × dispersion + 0,3 × symétrie
    La dispersion porte l'essentiel du poids : un trafic aléatoire peut être symétrique
    (des écarts uniformément répartis le sont), il n'est jamais resserré.

    score = 0,45 × régularité des intervalles
          + 0,35 × régularité des volumes      (orig_bytes + resp_bytes par connexion)
          + 0,20 × persistance                 (min(1, n × intervalle médian / durée observée) :
                                                la paire a-t-elle parlé sur toute la période,
                                                ou en une seule rafale ?)

    Lecture : >= 0.85 très régulier · 0.70 à 0.85 régulier · en dessous, peu probant.
    Le seuil n'est pas une vérité : il se règle sur le trafic normal de référence.

DESTINATION INÉDITE
    Avec --reference <conn.log de trafic normal>, chaque paire est marquée « inédite » si sa
    destination n'apparaît jamais dans la référence. Ce n'est pas un score, c'est un
    indice de contexte : un balisement vers une destination déjà vue mille fois est plus
    probablement une mise à jour qu'un C2.

DESTINATIONS INTERNES
    Avec --externes-seulement, seules les destinations publiques sont évaluées (sont
    écartées : plages privées RFC 1918, lien local, multicast, diffusion). Le trafic
    Windows interne est très régulier par nature — annonces NetBIOS toutes les ~5 min,
    renouvellements vers le contrôleur de domaine — et occupe sinon le haut du classement.
    L'option masque aussi un C2 interne (pivot) : ne l'utiliser qu'en le sachant.

EXEMPLES
    python3 balisement.py conn.log
    python3 balisement.py http.log --externes-seulement
    python3 balisement.py conn.log --reference normal/conn.log --seuil 0.8
    python3 balisement.py conn.log --ignorer exclusions.txt --format md > balisement.md

    exclusions.txt : une adresse IP ou un réseau CIDR par ligne, # pour commenter.
    Exclure précisément, jamais une plage entière par confort.

Auteur : Mamadou Lamine Thiore — module 03 du dépôt detection-lab.
"""

import argparse
import ipaddress
import json
import signal
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone


# --------------------------------------------------------------------------- lecture

def lire_journal(chemin):
    """Renvoie (type, événements). type = "conn" ou "http" ; chaque événement est un dict
    avec ts, src, dst, port, proto, service, octets."""
    evenements = []
    genre = None
    with open(chemin, encoding="utf-8", errors="replace") as f:
        premiere = f.readline()
        f.seek(0)
        if premiere.lstrip().startswith("{"):
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    e = json.loads(ligne)
                except json.JSONDecodeError:
                    continue
                if genre is None:
                    genre = "http" if "method" in e or "request_body_len" in e else "conn"
                evenements.append(_normaliser(e, genre))
        else:
            champs = None
            for ligne in f:
                ligne = ligne.rstrip("\n")
                if ligne.startswith("#fields"):
                    champs = ligne.split("\t")[1:]
                    genre = "http" if "request_body_len" in champs else "conn"
                    continue
                if ligne.startswith("#") or not ligne or champs is None:
                    continue
                valeurs = ligne.split("\t")
                evenements.append(_normaliser(dict(zip(champs, valeurs)), genre))
    return genre or "conn", [e for e in evenements if e is not None]


def _nombre(v):
    if v in (None, "", "-", "(empty)"):
        return 0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0


def _normaliser(e, genre):
    try:
        ts = float(e.get("ts"))
    except (TypeError, ValueError):
        return None
    if genre == "http":
        return {
            "ts": ts,
            "src": e.get("id.orig_h"),
            "dst": e.get("id.resp_h"),
            "port": str(e.get("id.resp_p")),
            "proto": "tcp",
            "service": "http " + (e.get("method") or "-"),
            "octets": _nombre(e.get("request_body_len")) + _nombre(e.get("response_body_len")),
        }
    return {
        "ts": ts,
        "src": e.get("id.orig_h"),
        "dst": e.get("id.resp_h"),
        "port": str(e.get("id.resp_p")),
        "proto": e.get("proto", "-"),
        "service": e.get("service") or "-",
        "octets": _nombre(e.get("orig_bytes")) + _nombre(e.get("resp_bytes")),
    }


def interne(adresse):
    """Vrai pour une destination non routable sur Internet (privée, lien local, multicast,
    diffusion). Une adresse illisible est traitée comme externe : on ne masque pas ce
    qu'on ne comprend pas."""
    try:
        ip = ipaddress.ip_address(adresse)
    except ValueError:
        return False
    return (ip.is_private or ip.is_link_local or ip.is_multicast
            or ip.is_loopback or ip == ipaddress.ip_address("255.255.255.255"))


def lire_exclusions(chemin):
    reseaux = []
    with open(chemin, encoding="utf-8") as f:
        for ligne in f:
            ligne = ligne.split("#", 1)[0].strip()
            if ligne:
                reseaux.append(ipaddress.ip_network(ligne, strict=False))
    return reseaux


def exclu(adresse, reseaux):
    try:
        ip = ipaddress.ip_address(adresse)
    except ValueError:
        return False
    return any(ip in r for r in reseaux)


# ----------------------------------------------------------------------- statistiques

def quartiles(valeurs):
    q = statistics.quantiles(valeurs, n=4, method="inclusive")
    return q[0], q[1], q[2]


def bowley(valeurs):
    """Asymétrie de Bowley : (Q1 + Q3 - 2·Q2) / (Q3 - Q1). 0 = symétrique."""
    q1, q2, q3 = quartiles(valeurs)
    # Garde-fou : si l'écart interquartile est négligeable devant la médiane, les valeurs
    # sont quasi identiques et l'asymétrie n'a plus de sens (deux tailles 4410 / 4412
    # donneraient sinon une asymétrie maximale).
    if q3 - q1 <= 0.01 * abs(q2):
        return 0.0
    return (q1 + q3 - 2 * q2) / (q3 - q1)


def mad(valeurs):
    m = statistics.median(valeurs)
    return statistics.median(abs(v - m) for v in valeurs)


def dispersion_relative(valeurs):
    m = statistics.median(valeurs)
    if m == 0:
        return 0.0 if mad(valeurs) == 0 else 1.0
    return min(1.0, mad(valeurs) / m)


def scorer(connexions):
    temps = sorted(c["ts"] for c in connexions)
    ecarts = [b - a for a, b in zip(temps, temps[1:])]
    tailles = [c["octets"] for c in connexions]

    def regularite(valeurs):
        disp = 1 - dispersion_relative(valeurs)
        sym = 1 - min(1.0, abs(bowley(valeurs)))
        return 0.7 * disp + 0.3 * sym, disp, sym

    reg_ts, disp_ts, sym_ts = regularite(ecarts)
    reg_vol, _, _ = regularite(tailles)
    duree = temps[-1] - temps[0]
    med_ecart = statistics.median(ecarts)
    persistance = min(1.0, len(temps) * med_ecart / duree) if duree > 0 else 0.0

    score = 0.45 * reg_ts + 0.35 * reg_vol + 0.20 * persistance
    gigue = (mad(ecarts) / med_ecart * 100) if med_ecart > 0 else 0.0
    return {
        "score": round(score, 3),
        "intervalles": round(reg_ts, 3),
        "volumes": round(reg_vol, 3),
        "persistance": round(persistance, 3),
        "connexions": len(temps),
        "intervalle_median_s": round(med_ecart, 1),
        "gigue_pct": round(gigue, 1),
        "octets_median": int(statistics.median(tailles)),
        "debut": temps[0],
        "fin": temps[-1],
    }


# ------------------------------------------------------------------------- sorties

def horodatage(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def niveau(score):
    if score >= 0.85:
        return "très régulier"
    if score >= 0.70:
        return "régulier"
    return "peu probant"


def main():
    # Sortie coupée par head ou less : terminer proprement, sans trace d'erreur.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    p = argparse.ArgumentParser(description="Score de balisement sur un conn.log ou un http.log de Zeek.")
    p.add_argument("journal", help="conn.log ou http.log de Zeek")
    p.add_argument("--reference", help="journal Zeek de trafic normal (destinations connues)")
    p.add_argument("--ignorer", help="fichier d'adresses ou réseaux CIDR à exclure")
    p.add_argument("--externes-seulement", action="store_true",
                   help="n'évaluer que les destinations publiques (écarte privé, multicast, diffusion)")
    p.add_argument("--min-connexions", type=int, default=20,
                   help="nombre minimal d'événements (connexions ou requêtes) par paire")
    p.add_argument("--duree-min", type=float, default=300.0,
                   help="durée d'activité minimale d'une paire, en secondes")
    p.add_argument("--seuil", type=float, default=0.0,
                   help="n'afficher que les paires au-dessus de ce score")
    p.add_argument("--top", type=int, default=20)
    p.add_argument("--format", choices=["texte", "md", "json"], default="texte")
    a = p.parse_args()

    genre, evenements = lire_journal(a.journal)
    if not evenements:
        sys.exit(f"Aucun événement lisible dans {a.journal}")
    unite = "requêtes" if genre == "http" else "connexions"

    exclusions = lire_exclusions(a.ignorer) if a.ignorer else []
    connues = None
    if a.reference:
        connues = {e["dst"] for e in lire_journal(a.reference)[1]}

    paires = defaultdict(list)
    internes = 0
    for e in evenements:
        if exclusions and (exclu(e["dst"], exclusions) or exclu(e["src"], exclusions)):
            continue
        if a.externes_seulement and interne(e["dst"]):
            internes += 1
            continue
        paires[(e["src"], e["dst"], e["port"])].append(e)

    resultats = []
    trop_courtes = 0
    for (src, dst, port), groupe in paires.items():
        if len(groupe) < a.min_connexions:
            continue
        temps = [g["ts"] for g in groupe]
        if max(temps) - min(temps) < a.duree_min:
            trop_courtes += 1
            continue
        r = scorer(groupe)
        if r["score"] < a.seuil:
            continue
        services = sorted({g["service"] for g in groupe})
        r.update({
            "src": src, "dst": dst, "port": port,
            "proto": groupe[0]["proto"], "service": ",".join(services),
            "niveau": niveau(r["score"]),
            "inedite": (dst not in connues) if connues is not None else None,
        })
        resultats.append(r)

    resultats.sort(key=lambda r: r["score"], reverse=True)
    resultats = resultats[: a.top]

    evaluees = sum(1 for g in paires.values() if len(g) >= a.min_connexions) - trop_courtes
    entete = (f"{genre}.log · {len(evenements)} {unite} lues · {len(paires)} paires · "
              f"{evaluees} évaluées (>= {a.min_connexions} {unite} sur >= {a.duree_min:.0f} s)"
              + (f" · {trop_courtes} écartées car trop brèves" if trop_courtes else "")
              + (f" · {internes} {unite} vers des destinations internes ignorées" if internes else ""))

    if a.format == "json":
        print(json.dumps({"journal": genre, "resume": entete, "paires": resultats},
                         ensure_ascii=False, indent=2))
        return

    if a.format == "md":
        print(f"# Balisement — `{a.journal}`\n\n{entete}\n")
        if not resultats:
            print("Aucune paire évaluable au-dessus du seuil.")
            return
        col = "Req." if genre == "http" else "Conn."
        print(f"| Score | Niveau | Source | Destination | Port | Service | {col} | Intervalle médian | Gigue | Octets médians | Inédite |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for r in resultats:
            ined = "—" if r["inedite"] is None else ("oui" if r["inedite"] else "non")
            print(f"| {r['score']} | {r['niveau']} | {r['src']} | {r['dst']} | {r['port']} | "
                  f"{r['service']} | {r['connexions']} | {r['intervalle_median_s']} s | "
                  f"{r['gigue_pct']} % | {r['octets_median']} | {ined} |")
        return

    print(entete)
    print()
    if not resultats:
        print("Aucune paire au-dessus du seuil.")
        return
    for r in resultats:
        ined = "" if r["inedite"] is None else ("  [destination inédite]" if r["inedite"] else "  [destination connue]")
        print(f"{r['score']:.3f}  {r['niveau']:<14} {r['src']} -> {r['dst']}:{r['port']} "
              f"({r['proto']}/{r['service']}){ined}")
        print(f"       {r['connexions']} {unite}, toutes les {r['intervalle_median_s']} s "
              f"(gigue {r['gigue_pct']} %), {r['octets_median']} octets médians, "
              f"du {horodatage(r['debut'])} au {horodatage(r['fin'])} UTC")
        print(f"       détail : intervalles {r['intervalles']} · "
              f"volumes {r['volumes']} · persistance {r['persistance']}")


if __name__ == "__main__":
    main()
