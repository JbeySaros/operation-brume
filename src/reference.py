"""Niveau 1 - Comprendre les donnees et etablir la reference « normale ».

    python3 src/reference.py --donnees donnees
"""
import pandas as pd

from chargement import charger, lire_args, montrer, titre

SOURCES = ["vpn", "proxy", "firewall", "mail", "ad", "edr"]


def analyser(d):
    inv, res = d["inventaire"], {}
    res["effectifs"] = {
        "postes": int((inv.type == "poste").sum()),
        "serveurs": int((inv.type == "serveur").sum()),
        "utilisateurs (proprietaires de poste)": int(inv.proprietaire.nunique()),
        "comptes distincts vus dans l AD": int(d["ad"].utilisateur.nunique()),
    }
    res["periode"] = (min(d[s].horodatage.min() for s in SOURCES),
                      max(d[s].horodatage.max() for s in SOURCES))
    # Volumes journaliers : MEDIANE (robuste a l attaque) en semaine / week-end
    lignes = []
    for s in SOURCES:
        # On compte les evenements par date, puis on separe les jours ouvrables et le week-end.
        j = d[s].groupby(d[s].horodatage.dt.date).size()
        jour = pd.to_datetime(j.index).dayofweek
        # Cette proportion decrit les horaires des evenements survenus en semaine.
        ouvres = d[s][d[s].horodatage.dt.dayofweek < 5]
        part = ((ouvres.horodatage.dt.hour >= 8) & (ouvres.horodatage.dt.hour < 18)).mean()
        lignes.append({"source": s, "lignes": len(d[s]),
                       "mediane_jour_ouvre": int(j[jour < 5].median()),
                       "mediane_week_end": int(j[jour >= 5].median()) if (jour >= 5).any() else 0,
                       "part_8h_18h_en_semaine_%": round(100 * part, 1)})
    res["volumes"] = pd.DataFrame(lignes)
    # Les differences avec l'inventaire sont conservees comme pistes d'enquete.
    H, IP, P = set(inv.hostname), set(inv.ip), set(inv.proprietaire.dropna())
    res["hors_inventaire"] = {
        "AD utilisateur": sorted(set(d["ad"].utilisateur) - P),
        "AD ip_source": sorted(set(d["ad"].ip_source) - H - IP),
        "pare-feu ip_source": sorted(set(d["firewall"].ip_source) - IP),
        "EDR utilisateur": sorted(set(d["edr"].utilisateur) - P),
    }
    # Une IP partagee peut rendre ambigue une jointure reseau vers une machine ou un proprietaire.
    res["ip_en_double"] = inv[inv.ip.duplicated(keep=False)].sort_values("ip")
    return res


def main():
    # Le script produit un rapport de reference a partir du chargeur commun.
    d = charger(lire_args(__doc__).donnees)
    r = analyser(d)
    titre("Effectifs")
    for k, v in r["effectifs"].items():
        print(f"  {k:42} {v}")
    print(f"  periode : {r['periode'][0]:%Y-%m-%d %H:%M} -> {r['periode'][1]:%Y-%m-%d %H:%M} (heure de Paris)")
    titre("Une journee normale : volumes (medianes) et part des evenements 8h-18h")
    montrer(r["volumes"])
    # Les derniers tableaux signalent les identifiants absents ou ambigus sans les exclure.
    titre("Cles absentes de l inventaire (a investiguer)")
    for k, v in r["hors_inventaire"].items():
        print(f"  {k:20} {v}")
    titre("Adresses IP partagees par 2 postes dans l inventaire (piege de jointure)")
    montrer(r["ip_en_double"], ["hostname", "ip", "site", "proprietaire"])


if __name__ == "__main__":
    main()
