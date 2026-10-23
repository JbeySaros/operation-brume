"""Chargement commun des sept sources de l Operation Brume + petits utilitaires.

Choix assumes :
  * tous les horodatages sont convertis en heure de Paris (tz-aware) ;
  * chaque ligne garde sa position dans le fichier source (colonne `ligne`)
    pour citer une preuve du type  vpn_auth.csv:L1349  dans le rapport ;
  * les valeurs vides sont structurelles (motif vide = connexion reussie...) :
    on ne fait JAMAIS de dropna global.
"""
import argparse
import json
from pathlib import Path

import pandas as pd

TZ = "Europe/Paris"
FICHIERS = {"vpn": "vpn_auth.csv", "proxy": "proxy_web.csv", "firewall": "firewall.csv",
            "mail": "mail_gateway.csv", "ad": "ad_events.jsonl",
            "edr": "edr_alerts.json", "inventaire": "inventaire_parc.csv"}


def _horodatage(df):
    # UTC est d'abord impose pour obtenir un repere commun avant la conversion locale.
    df["horodatage"] = pd.to_datetime(df["horodatage"], utc=True).dt.tz_convert(TZ)
    return df


def charger(dossier):
    # Le dictionnaire rassemble toutes les sources sous des noms courts communs aux analyses.
    dossier = Path(dossier)
    d = {}
    # Les CSV ont une ligne d'en-tete : les numeros de preuve commencent a la ligne 2.
    for nom in ["vpn", "proxy", "firewall", "mail"]:
        df = pd.read_csv(dossier / FICHIERS[nom])
        df["ligne"] = df.index + 2
        d[nom] = _horodatage(df)
    # Dans le JSON Lines, chaque ligne est un evenement et sert directement de numero de preuve.
    with open(dossier / FICHIERS["ad"], encoding="utf-8") as f:
        ad = pd.DataFrame(json.loads(l) for l in f)
    ad["ligne"] = ad.index + 1
    d["ad"] = _horodatage(ad)
    # Le JSON EDR est une liste : l'identifiant d'alerte remplace le numero de ligne.
    with open(dossier / FICHIERS["edr"], encoding="utf-8") as f:
        edr = pd.DataFrame(json.load(f))
    edr["ligne"] = edr["id"]
    d["edr"] = _horodatage(edr)
    # L'inventaire n'a pas de colonne d'horodatage, mais conserve aussi la ligne source.
    inv = pd.read_csv(dossier / FICHIERS["inventaire"])
    inv["ligne"] = inv.index + 2
    d["inventaire"] = inv
    return d


def preuve(source, ligne):
    """Reference de preuve lisible : fichier:Lnumero (ou fichier#id pour l EDR)."""
    # L'EDR se reference par identifiant ; les autres sources utilisent un numero de ligne.
    if source == "edr":
        return f"{FICHIERS[source]}#{ligne}"
    return f"{FICHIERS[source]}:L{ligne}"


def preuves(source, lignes):
    """Plage de preuves : L5651-5658 si contigu, sinon liste."""
    # Le tri permet de detecter une suite continue et de la raccourcir en plage.
    l = sorted(int(x) for x in lignes)
    if len(l) > 1 and l[-1] - l[0] == len(l) - 1:
        return f"{FICHIERS[source]}:L{l[0]}-{l[-1]}"
    return f"{FICHIERS[source]}:L" + ",".join(map(str, l))


def evenement(ts, phase, preuve_txt, texte):
    """Une ligne de la frise chronologique commune."""
    # Le dictionnaire fixe le schema partage par les analyses de chronologie.
    return {"horodatage": ts, "phase": phase, "preuve": preuve_txt, "evenement": texte}


def est_interne(adresse):
    """Vrai pour un nom de poste ou une IP du plan d adressage Nordis (10.x)."""
    # Les noms d'hotes sont assimiles aux adresses internes ; seules les IP hors 10/8 sont externes.
    a = str(adresse)
    return a.startswith("10.") or not a.replace(".", "").isdigit()


def lire_args(description):
    # Les scripts partagent la meme option pour choisir le dossier de donnees.
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--donnees", type=Path, default=Path("donnees"))
    return p.parse_args()


def titre(texte):
    # Un titre separe visuellement les blocs du rapport console.
    print("\n" + "=" * 78 + f"\n{texte}\n" + "=" * 78)


def montrer(df, colonnes=None):
    """Affichage compact d un DataFrame (sans index)."""
    # Les options limitent les retours a la ligne et evitent de tronquer les preuves.
    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 55)
    print((df if colonnes is None else df[colonnes]).to_string(index=False))
