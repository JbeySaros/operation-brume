"""Niveau 4 - Mesurer l'impact : exfiltration, alertes EDR ignorées, périmètre touché.

    python3 src/impact.py --donnees donnees
"""
import pandas as pd

from chargement import (charger, evenement, lire_args, montrer, preuve, preuves,
                        titre)

FACTEUR_ENVOI = 100   # une requête qui envoie 100x plus que le p99 des envois est « hors norme »


def exfiltration(d):
    """Requêtes dont le volume ENVOYÉ est hors norme, regroupées par destination."""
    p = d["proxy"]
    p99 = p.octets_envoyes.quantile(0.99)
    # Seules les requetes tres au-dessus de ce niveau servent de transferts candidats.
    gros = p[p.octets_envoyes > FACTEUR_ENVOI * p99]
    if gros.empty:
        return gros, None, p99
    # Le regroupement distingue compte, source, destination, chemin et methode HTTP.
    g = gros.groupby(["login", "ip_source", "host", "url", "methode"]).agg(
        requetes=("ligne", "size"), debut=("horodatage", "min"), fin=("horodatage", "max"),
        octets=("octets_envoyes", "sum"), min_requete=("octets_envoyes", "min"),
        max_requete=("octets_envoyes", "max"), premiere=("ligne", "min"), derniere=("ligne", "max"),
        statuts=("statut", lambda s: sorted(s.unique()))).reset_index()
    # première apparition de l'hôte dans tout le journal : un hôte jamais vu avant est un indice
    g["premier_passage_hote"] = g.host.map(p.groupby("host").horodatage.min())
    # Ces colonnes replacent chaque transfert candidat dans l'historique global de son hote.
    g["requetes_totales_hote"] = g.host.map(p.groupby("host").size())
    return gros, g, p99


def alertes_edr(d):
    """Alertes non closes + pourquoi elles ont pu passer inaperçues (statistiques de bruit)."""
    e = d["edr"].copy()
    e["heure"] = e.horodatage.dt.hour
    e["hors_horaires"] = (e.heure < 7) | (e.heure >= 19) | (e.horodatage.dt.dayofweek >= 5)
    ouvertes = e[e.statut == "ouvert"].sort_values("horodatage")
    stats = {
        "total": len(e), "ouvertes": len(ouvertes), "faux_positifs": int((e.statut == "clos_faux_positif").sum()),
        "fp_hors_horaires": int(((e.statut == "clos_faux_positif") & e.hors_horaires).sum()),
        "ouvertes_hors_horaires": int(ouvertes.hors_horaires.sum()),
        "alertes_par_jour": round(len(e) / e.horodatage.dt.date.nunique(), 1),
        "par_titre": e.groupby(["titre", "gravite", "statut"]).size().reset_index(name="nb"),
    }
    return ouvertes, stats


def perimetre(d, ip_ext, flux_pivot):
    """Une ligne par machine touchée, avec un niveau de certitude et la source qui le prouve.

    Une authentification AD réussie est confirmee par un evenement 4624.
    Un flux pare-feu autorise ou une alerte EDR est rapporte separement, sans conclure a une session.
    Des refus AD seuls indiquent une tentative, sans authentification reussie observee.
    """
    ad, inv = d["ad"], d["inventaire"]
    lignes = []
    a = ad[ad.ip_source == ip_ext]
    # Les evenements AD depuis l'IP externe sont distingues selon leur code de succes ou d'echec.
    for m, g in a.groupby("machine_cible"):
        auth = g[g.event_id == 4624]
        hors_echec = g[g.event_id != 4625]
        niveau = "authentification AD réussie" if len(auth) else "évènements AD sans 4624"
        lignes.append({"machine": m, "auth_confirmee": len(auth) > 0, "niveau": niveau,
                       "preuve": f"AD : {len(auth)} authentifications réussies, {len(g) - len(auth)} autres évènements ({', '.join(map(str, sorted(hors_echec.event_id.unique())))} hors échecs)",
                       "comptes": ", ".join(sorted(g.utilisateur.unique()))})
    if flux_pivot is not None:
        rdp = flux_pivot[(flux_pivot.action == "autorise") & (flux_pivot.port_dest == 3389)]
        for m, g in rdp.groupby("serveur"):
            lignes.append({"machine": m, "auth_confirmee": False, "niveau": "flux RDP autorisé (session non confirmée)",
                           "preuve": f"pare-feu : {len(g)} flux RDP autorisés depuis le pivot", "comptes": ""})
    # Les alertes EDR ouvertes sont rattachees aux machines qu'elles nomment.
    for m, g in d["edr"][d["edr"].statut == "ouvert"].groupby("machine"):
        lignes.append({"machine": m, "auth_confirmee": False, "niveau": "alerte EDR (accès non confirmé)",
                       "preuve": f"EDR : {', '.join(g.titre)}", "comptes": ", ".join(sorted(g.utilisateur.unique()))})
    toutes = pd.DataFrame(lignes)
    # Les lignes provenant de plusieurs sources sont reunies en un niveau et des preuves cumulees.
    t = toutes.groupby("machine").agg(
        auth_confirmee=("auth_confirmee", "any"), niveau=("niveau", lambda s: " | ".join(sorted(set(s)))),
        preuves=("preuve", " | ".join),
        comptes=("comptes", lambda s: ", ".join(sorted({c for x in s for c in x.split(", ") if c})))).reset_index()
    # serveurs jamais vus dans l'analyse = non touchés (preuve négative)
    manquants = sorted(set(inv[inv.type == "serveur"].hostname) - set(t.machine))
    return t.sort_values(["auth_confirmee", "machine"], ascending=[False, True]).drop(columns="auth_confirmee"), manquants


def analyser(d, ip_ext=None, flux_pivot=None):
    res, evts = {}, []
    gros, g, p99 = exfiltration(d)
    ouvertes, stats = alertes_edr(d)
    # Les resultats detailles sont conserves pour les IOC et le rapport de sortie.
    res.update(p99_envoi=p99, transferts=g, alertes_ouvertes=ouvertes, stats_edr=stats)
    if g is not None:
        for _, x in g.iterrows():
            go, gio = x.octets / 1e9, x.octets / 2 ** 30
            evts.append(evenement(x.debut, "5 Exfiltration", preuves("proxy", gros.ligne),
                f"{x.requetes} requêtes {x.methode} {x.host}{x.url} depuis {x.ip_source} ({x.login}) : "
                f"{x.octets:,} octets envoyés = {go:.3f} Go (soit {gio:.3f} Gio) jusqu'à {x.fin:%H:%M:%S}".replace(",", " ")))
        res["octets_exfiltres"] = int(g.octets.sum())
    phases = {"Page d'hameçonnage visitée": "1 Accès initial", "Création de compte à privilèges hors procédure": "4 Privilèges et persistance",
              "Exfiltration de données probable": "5 Exfiltration", "Suppression de sauvegardes": "6 Sabotage", "Comportement de rançongiciel": "6 Sabotage"}
    # Les alertes deja ajoutees par entree.py sont exclues pour eviter un doublon dans la frise.
    for _, a in ouvertes.iterrows():
        if a.titre == "Page d'hameçonnage visitée":
            continue  # déjà dans la frise via entree.py
        evts.append(evenement(a.horodatage, phases.get(a.titre, "6 Sabotage"), preuve("edr", a.id),
                              f"Alerte EDR « {a.titre} » sur {a.machine} ({a.utilisateur}), gravité {a.gravite}, statut {a.statut}"))
    if ip_ext:
        res["perimetre"], res["serveurs_non_touches"] = perimetre(d, ip_ext, flux_pivot)
    return res, evts


def main():
    d = charger(lire_args(__doc__).donnees)
    import entree, progression
    # Les analyses precedentes fournissent les adresses necessaires pour attribuer l'impact.
    e, _ = entree.analyser(d)
    p, _ = progression.analyser(d, e.get("ip_attaquant"))
    r, _ = analyser(d, e.get("ip_attaquant"), p.get("pivot_apres_scan"))
    titre("4a. Exfiltration : envois hors norme (> 100 x le p99 des octets envoyés)")
    print(f"p99 des octets envoyés (toutes requêtes) = {r['p99_envoi']:.0f} o  → seuil = {FACTEUR_ENVOI * r['p99_envoi']:,.0f} o".replace(",", " "))
    if r["transferts"] is not None:
        montrer(r["transferts"], ["login", "ip_source", "host", "url", "methode", "requetes", "debut", "fin", "min_requete", "max_requete", "statuts", "premiere", "derniere", "premier_passage_hote", "requetes_totales_hote"])
        o = r["octets_exfiltres"]
        print(f"\nTOTAL ENVOYÉ : {o:,} octets = {o / 1e9:.3f} Go (décimal) = {o / 2 ** 30:.3f} Gio".replace(",", " "))
        dur = (r["transferts"].fin.iloc[0] - r["transferts"].debut.iloc[0]).total_seconds()
        print(f"Durée {dur / 60:.1f} min, débit moyen ≈ {o * 8 / dur / 1e6:.1f} Mbit/s. Limite : seul le proxy voit ce flux (le pare-feu ne journalise que du trafic interne).")
    titre("4b. Alertes EDR non closes")
    montrer(r["alertes_ouvertes"], ["ligne", "horodatage", "machine", "utilisateur", "titre", "gravite", "statut"])
    s = r["stats_edr"]
    print(f"\nContexte de bruit : {s['total']} alertes, {s['faux_positifs']} closes en faux positif ({100 * s['faux_positifs'] / s['total']:.1f} %), "
          f"≈ {s['alertes_par_jour']} alertes/jour ; faux positifs hors horaires ouvrés : {s['fp_hors_horaires']} ; "
          f"alertes ouvertes hors horaires ouvrés : {s['ouvertes_hors_horaires']}/{s['ouvertes']}.")
    print("Hypothèses (non prouvées par les journaux) : alerte noyée dans le bruit, aucune astreinte de nuit/week-end, pas d'escalade automatique pour 'critique'.")
    montrer(s["par_titre"])
    if "perimetre" in r:
        titre("4c. Périmètre touché (machines)")
        montrer(r["perimetre"], ["machine", "niveau", "comptes", "preuves"])
        print(f"Serveurs sans autre trace que le balayage initial : {r['serveurs_non_touches'] or 'aucun'}")
        print("Limite : le journal ne permet pas de savoir QUELS fichiers ont été lus, copiés ou chiffrés (seule l'EDR cite FILE01 pour le chiffrement).")


if __name__ == "__main__":
    main()
