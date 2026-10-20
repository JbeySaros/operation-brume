#!/usr/bin/env python3
"""
Script de démarrage — projet « Opération Brume ».

Charge les différentes sources avec pandas et affiche quelques repères.
À vous de l'étendre pour reconstituer l'attaque. Ce fichier ne contient
AUCUNE réponse : c'est un point de départ.

    pip install pandas
    python3 demarrage.py --donnees ./donnees
"""
import argparse
import json
from pathlib import Path

import pandas as pd


def charger(dossier: Path) -> dict:
    data = {}
    data["vpn"] = pd.read_csv(dossier / "vpn_auth.csv", parse_dates=["horodatage"])
    data["proxy"] = pd.read_csv(dossier / "proxy_web.csv", parse_dates=["horodatage"])
    data["firewall"] = pd.read_csv(dossier / "firewall.csv", parse_dates=["horodatage"])
    data["mail"] = pd.read_csv(dossier / "mail_gateway.csv", parse_dates=["horodatage"])
    data["inventaire"] = pd.read_csv(dossier / "inventaire_parc.csv")
    # JSON Lines : un objet par ligne
    with open(dossier / "ad_events.jsonl", encoding="utf-8") as f:
        data["ad"] = pd.DataFrame(json.loads(l) for l in f)
    data["ad"]["horodatage"] = pd.to_datetime(data["ad"]["horodatage"])
    # JSON classique (liste d'objets)
    with open(dossier / "edr_alerts.json", encoding="utf-8") as f:
        data["edr"] = pd.DataFrame(json.load(f))
    return data


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--donnees", type=Path, default=Path("donnees"))
    args = p.parse_args()
    data = charger(args.donnees)

    print("=== Volumes ===")
    for nom, df in data.items():
        print(f"  {nom:12} {len(df):>7} lignes")

    print("\n=== Période couverte (VPN) ===")
    print(" ", data["vpn"].horodatage.min(), "->", data["vpn"].horodatage.max())

    print("\n=== Exemple : connexions VPN par résultat ===")
    print(data["vpn"].resultat.value_counts().to_string())

    print("\n=== À vous de jouer ===")
    print("  Pistes : connexions depuis l'étranger ? échecs répétés puis succès ?")
    print("           comptes créés la nuit ? gros volumes sortants ? IP inconnues ?")


if __name__ == "__main__":
    main()
