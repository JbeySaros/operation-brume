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
    df["horodatage"] = pd.to_datetime(df["horodatage"], utc=True).dt.tz_convert(TZ)
    return df


def charger(dossier):
    dossier = Path(dossier)
    d = {}
    # CSV : ligne 1 = en-tete, donc la premiere donnee est la ligne 2
    for nom in ["vpn", "proxy", "firewall", "mail"]:
        df = pd.read_csv(dossier / FICHIERS[nom])
        df["ligne"] = df.index + 2
        d[nom] = _horodatage(df)
    # JSON Lines : une ligne = un objet, la premiere donnee est la ligne 1
    with open(dossier / FICHIERS["ad"], encoding="utf-8") as f:
        ad = pd.DataFrame(json.loads(l) for l in f)
    ad["ligne"] = ad.index + 1
    d["ad"] = _horodatage(ad)
    # JSON classique : une alerte est identifiee par son id (EDR-xxxxx)
    with open(dossier / FICHIERS["edr"], encoding="utf-8") as f:
        edr = pd.DataFrame(json.load(f))
    edr["ligne"] = edr["id"]
    d["edr"] = _horodatage(edr)
    inv = pd.read_csv(dossier / FICHIERS["inventaire"])
    inv["ligne"] = inv.index + 2
    d["inventaire"] = inv
    return d


def preuve(source, ligne):
    """Reference de preuve lisible : fichier:Lnumero (ou fichier#id pour l EDR)."""
    if source == "edr":
        return f"{FICHIERS[source]}#{ligne}"
    return f"{FICHIERS[source]}:L{ligne}"


def preuves(source, lignes):
    """Plage de preuves : L5651-5658 si contigu, sinon liste."""
    l = sorted(int(x) for x in lignes)
    if len(l) > 1 and l[-1] - l[0] == len(l) - 1:
        return f"{FICHIERS[source]}:L{l[0]}-{l[-1]}"
    return f"{FICHIERS[source]}:L" + ",".join(map(str, l))


def evenement(ts, phase, preuve_txt, texte):
    """Une ligne de la frise chronologique commune."""
    return {"horodatage": ts, "phase": phase, "preuve": preuve_txt, "evenement": texte}


def est_interne(adresse):
    """Vrai pour un nom de poste ou une IP du plan d adressage Nordis (10.x)."""
    a = str(adresse)
    return a.startswith("10.") or not a.replace(".", "").isdigit()


def lire_args(description):
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--donnees", type=Path, default=Path("donnees"))
    return p.parse_args()


def titre(texte):
    print("\n" + "=" * 78 + f"\n{texte}\n" + "=" * 78)


def montrer(df, colonnes=None):
    """Affichage compact d un DataFrame (sans index)."""
    pd.set_option("display.width", 220)
    pd.set_option("display.max_colwidth", 55)
    print((df if colonnes is None else df[colonnes]).to_string(index=False))
