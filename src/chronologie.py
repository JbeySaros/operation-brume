"""Niveau 5 - Frise chronologique commune + indicateurs de compromission (IOC).

    python3 src/chronologie.py --donnees donnees [--sorties sorties]

Assemble les évènements trouvés par entree.py, progression.py et impact.py,
les trie dans le temps et exporte deux CSV rejouables :
    sorties/chronologie.csv   (horodatage, phase, preuve, évènement)
    sorties/ioc.csv           (type, valeur, rôle, confiance, preuve)
"""
import argparse
from pathlib import Path

import pandas as pd

import entree
import impact
import progression
from chargement import charger, montrer, preuve, titre


def construire(d):
    e, ev1 = entree.analyser(d)
    p, ev2 = progression.analyser(d, e.get("ip_attaquant"))
    i, ev3 = impact.analyser(d, e.get("ip_attaquant"), p.get("pivot_apres_scan"))
    frise = pd.DataFrame(ev1 + ev2 + ev3).sort_values("horodatage", kind="stable").reset_index(drop=True)
    frise["horodatage"] = frise.horodatage.dt.strftime("%Y-%m-%d %H:%M:%S%z")
    return frise, e, p, i


def indicateurs(e, p, i):
    m, lignes = e["mail"], []
    def add(type_, valeur, role, confiance, pr):
        lignes.append({"type": type_, "valeur": valeur, "role": role, "confiance": confiance, "preuve": pr})
    add("courriel", m.expediteur, "expéditeur du courriel piégé (domaine sosie de " + str(m.sosie_de) + ")", "élevée", preuve("mail", m.ligne))
    add("fichier", m.piece_jointe, "pièce jointe à double extension", "élevée", preuve("mail", m.ligne))
    add("url", m.lien, "page d'hameçonnage", "élevée", preuve("mail", m.ligne))
    add("domaine", e["domaine_hameconnage"], "hameçonnage (domaine imitant un service interne)", "élevée", "proxy_web.csv:L" + ",".join(map(str, e["visites"].ligne)))
    add("compte", e["victime"], f"compte compromis en premier (poste {e['poste']})", "élevée", "proxy + VPN + EDR-10203")
    add("ip", e["ip_attaquant"], "IP externe de l'attaquant (VPN + AD) ; 4 pays déclarés pour une seule IP", "élevée", "vpn_auth.csv:L" + ",".join(map(str, e["vpn_ip"].ligne)))
    for _, r in p["rafales"].iterrows():
        if pd.notna(r.succes_ensuite):
            add("compte", r.utilisateur, "compte à privilèges compromis (rafale d'échecs puis succès RDP)", "élevée", r.lignes_echecs + f", ad_events.jsonl:L{r.ligne_succes}")
    for _, c in p["creations"][p["creations"].suspect].iterrows():
        add("compte", c.compte, "compte de persistance créé de nuit et ajouté à « " + str(c.groupe_admin) + " »", "élevée", f"ad_events.jsonl:L{c.ligne},L{c.ligne_ajout}")
    if "ip_pivot" in p:
        add("ip", p["ip_pivot"], "IP interne absente de l'inventaire : balayage puis RDP vers les serveurs (lien avec l'IP externe SUPPOSÉ : concordance horaire)", "moyenne", "firewall.csv:L" + str(p["scans"].iloc[0].premiere) + "-" + str(p["scans"].iloc[0].derniere))
    if i["transferts"] is not None:
        t = i["transferts"].iloc[0]
        add("domaine", t.host, "destination de l'exfiltration (jamais vue avant le transfert)", "élevée", f"proxy_web.csv:L{t.premiere}-{t.derniere}")
        add("url", f"https://{t.host}{t.url}", f"{int(t.requetes)} POST, {t.octets / 1e9:.3f} Go", "élevée", f"proxy_web.csv:L{t.premiere}-{t.derniere}")
    for _, r in i.get("perimetre", pd.DataFrame()).iterrows():
        add("machine", r.machine, r.niveau, "élevée" if r.niveau == "accès réussi" else "faible", r.preuves)
    return pd.DataFrame(lignes)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--donnees", type=Path, default=Path("donnees"))
    ap.add_argument("--sorties", type=Path, default=Path("sorties"))
    a = ap.parse_args()
    d = charger(a.donnees)
    frise, e, p, i = construire(d)
    ioc = indicateurs(e, p, i)
    a.sorties.mkdir(exist_ok=True)
    frise.to_csv(a.sorties / "chronologie.csv", index=False, encoding="utf-8")
    ioc.to_csv(a.sorties / "ioc.csv", index=False, encoding="utf-8")
    titre(f"Chronologie ({len(frise)} évènements) → {a.sorties / 'chronologie.csv'}")
    pd.set_option("display.max_colwidth", 120)
    for _, r in frise.iterrows():
        print(f"{r.horodatage[:19]}  [{r.phase}]\n    {r.evenement}\n    preuve : {r.preuve}")
    titre(f"Indicateurs de compromission ({len(ioc)}) → {a.sorties / 'ioc.csv'}")
    montrer(ioc, ["type", "valeur", "role", "confiance"])


if __name__ == "__main__":
    main()
