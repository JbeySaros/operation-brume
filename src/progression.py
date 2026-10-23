"""Niveau 3 - Suivre la progression : sondage, balayage interne, compte privilégié, persistance.

    python3 src/progression.py --donnees donnees

Quatre détections indépendantes, chacune avec un seuil explicite et justifié
par la distribution « normale » des données (voir reference.py).
"""
import pandas as pd

from chargement import (charger, est_interne, evenement, lire_args, montrer,
                        preuve, preuves, titre)

SEUIL_ECHECS, FENETRE_ECHECS = 5, pd.Timedelta("10min")   # >= 5 échecs à moins de 10 min d'écart
SEUIL_COUPLES, FENETRE_SCAN = 10, "1min"                  # >= 10 couples (serveur, port) en 1 min


def franchissements_glissants(g, seuil, fenetre):
    """Retourne les premieres lignes qui atteignent le seuil dans une fenetre glissante."""
    if g.empty:
        return g
    duree = pd.Timedelta(fenetre)
    temps = g.horodatage.tolist()
    debut, alerte_active, indices = 0, False, []
    for fin, horodatage in enumerate(temps):
        while horodatage - temps[debut] > duree:
            debut += 1
        atteint = fin - debut + 1 >= seuil
        if atteint and not alerte_active:
            indices.append(fin)
        alerte_active = atteint
    return g.iloc[indices]


def est_groupe_admin(groupe):
    """Reconnaît les groupes dont le nom indique un rôle d'administration."""
    return isinstance(groupe, str) and any(mot in groupe.casefold() for mot in ("admin", "administrateur"))


def franchissements_serveurs_glissants(g, seuil, fenetre):
    """Retourne le premier evenement atteignant le nombre de serveurs dans la fenetre."""
    if g.empty:
        return g
    duree = pd.Timedelta(fenetre)
    temps = g.horodatage.tolist()
    serveurs = g.machine_cible.tolist()
    debut, alert_active, comptes, indices = 0, False, {}, []
    for fin, horodatage in enumerate(temps):
        serveur = serveurs[fin]
        comptes[serveur] = comptes.get(serveur, 0) + 1
        while horodatage - temps[debut] > duree:
            ancien = serveurs[debut]
            comptes[ancien] -= 1
            if comptes[ancien] == 0:
                del comptes[ancien]
            debut += 1
        atteint = len(comptes) >= seuil
        if atteint and not alert_active:
            indices.append(fin)
        alert_active = atteint
    return g.iloc[indices]


def rafales_echecs(d):
    """Épisodes de >= 5 échecs (4625) d'un même couple (compte, source), puis ce qui suit."""
    ad = d["ad"].sort_values("horodatage")
    sorties = []
    for (u, src), g in ad[ad.event_id == 4625].groupby(["utilisateur", "ip_source"]):
        g = g.reset_index(drop=True)
        # Une alerte part au premier franchissement de cinq échecs dans toute fenêtre de dix minutes.
        for _, declenchement in franchissements_glissants(g, SEUIL_ECHECS, FENETRE_ECHECS).iterrows():
            fin = declenchement.horodatage
            e = g[(g.horodatage >= fin - FENETRE_ECHECS) & (g.horodatage <= fin)]
            suite = ad[(ad.utilisateur == u) & (ad.ip_source == src) & (ad.horodatage > fin)
                       & (ad.horodatage <= fin + pd.Timedelta("1h"))]
            ok = suite[suite.event_id == 4624].head(1)
            sorties.append({
                "utilisateur": u, "source": src, "debut": e.horodatage.min(), "fin": fin, "nb_echecs": len(e),
                "serveurs": ", ".join(sorted(e.machine_cible.unique())),
                "motif": ", ".join(sorted(e.motif.dropna().unique())),
                "lignes_echecs": preuves("ad", e.ligne),
                "succes_ensuite": ok.iloc[0].horodatage if len(ok) else pd.NaT,
                "type_connexion": ok.iloc[0].type_connexion if len(ok) else None,
                "ligne_succes": int(ok.iloc[0].ligne) if len(ok) else None,
                "suite_ad": suite[suite.event_id != 4624]})
    return pd.DataFrame(sorties)


def balayages(d):
    """Sources qui touchent >= 10 couples (serveur, port) distincts dans la même minute."""
    fw = d["firewall"].copy()
    fw["fenetre"] = fw.horodatage.dt.floor(FENETRE_SCAN)
    fw["couple"] = fw.ip_dest + ":" + fw.port_dest.astype(str)
    g = fw.groupby(["ip_source", "fenetre"]).agg(
        couples=("couple", "nunique"), flux=("ligne", "size"), bloques=("action", lambda a: (a == "bloque").sum()),
        premiere=("ligne", "min"), derniere=("ligne", "max"), ports=("port_dest", lambda p: [int(x) for x in sorted(p.unique())])).reset_index()
    normal_max = int(g[g.couples < SEUIL_COUPLES].couples.max())
    scans = g[g.couples >= SEUIL_COUPLES].copy()
    scans["dans_inventaire"] = scans.ip_source.isin(d["inventaire"].ip)
    scans["taux_blocage_%"] = (100 * scans.bloques / scans.flux).round(0)
    return scans, normal_max, 100 * (fw.action == "bloque").mean()


def activite_pivot(d, ip):
    """Tous les flux de l'IP suspecte HORS balayage, avec le nom du serveur visé."""
    serveurs = d["inventaire"][d["inventaire"].type == "serveur"].set_index("ip").hostname
    fw = d["firewall"]
    x = fw[fw.ip_source == ip].copy()
    x["serveur"] = x.ip_dest.map(serveurs)
    return x


def comptes_crees(d):
    """Chaque création de compte (4720) examinée selon 5 critères."""
    ad, inv = d["ad"], d["inventaire"]
    ajouts = ad[ad.event_id == 4728]
    lignes = []
    for _, c in ad[ad.event_id == 4720].iterrows():
        h = c.horodatage
        # L'ajout doit viser le compte cree, venir du meme acteur et de la meme source sous une heure.
        a = ajouts[(ajouts.compte_ajoute == c.compte_cree) & (ajouts.utilisateur == c.utilisateur)
                   & (ajouts.ip_source == c.ip_source) & (ajouts.horodatage >= h)
                   & (ajouts.horodatage <= h + pd.Timedelta("1h"))
                   & ajouts.groupe.map(est_groupe_admin)]
        # Seules les authentifications du compte apres sa creation sont comptees.
        co = ad[(ad.utilisateur == c.compte_cree) & (ad.event_id == 4624) & (ad.horodatage > h)]
        r = {"ligne": c.ligne, "horodatage": h, "compte": c.compte_cree, "cree_par": c.utilisateur, "depuis": c.ip_source,
             "nuit(22h-6h)": h.hour >= 22 or h.hour < 6, "week-end": h.dayofweek >= 5,
             "source_externe": not est_interne(c.ip_source),
             "groupe_admin": a.groupe.iloc[0] if len(a) else None,
             "connexions_ensuite": len(co), "ligne_ajout": int(a.ligne.iloc[0]) if len(a) else None}
        r["suspect"] = bool(r["groupe_admin"]) and (r["nuit(22h-6h)"] or r["source_externe"])
        lignes.append(r)
    return pd.DataFrame(lignes)


def couverture_vpn(d, ip_ext, ip_pivot):
    """Part de l'activité de l'attaquant (AD + pare-feu) qui tombe dans une session VPN journalisée."""
    # Les sessions reussies forment des intervalles temporels associes a l'IP externe.
    v = d["vpn"][(d["vpn"].ip_source == ip_ext) & (d["vpn"].resultat == "succes")].copy()
    v["fin"] = v.horodatage + pd.to_timedelta(v.duree_min, unit="m")
    def dans(t):
        # Une activite est couverte si son heure tombe dans au moins un de ces intervalles.
        return bool(((v.horodatage <= t) & (v.fin >= t)).any())
    ad = d["ad"][d["ad"].ip_source == ip_ext]
    fw = d["firewall"][d["firewall"].ip_source == ip_pivot]
    fw = fw[fw.horodatage > fw.horodatage.min() + pd.Timedelta("1h")]  # hors balayage initial
    ad_ok, fw_ok = ad.horodatage.map(dans), fw.horodatage.map(dans)
    return ad.assign(dans_session=ad_ok), fw.assign(dans_session=fw_ok)


def analyser(d, ip_ext=None):
    # Les signaux sont d'abord calcules par famille, puis transformes en evenements de frise.
    res, evts = {}, []
    rafales = rafales_echecs(d)
    scans, normal_max, taux_base = balayages(d)
    creations = comptes_crees(d)
    res.update(rafales=rafales, scans=scans, scan_normal_max=normal_max, taux_blocage_base=taux_base, creations=creations)
    ad = d["ad"]

    # Une rafale est datee a son premier echec ; son succes ulterieur est ajoute comme evenement distinct.
    for _, r in rafales.iterrows():
        evts.append(evenement(r.debut, "3 Progression", r.lignes_echecs,
            f"{r.nb_echecs} échecs d'authentification sur {r.utilisateur} depuis {r.source} ({r.motif}) sur {r.serveurs}"))
        if pd.notna(r.succes_ensuite):
            evts.append(evenement(r.succes_ensuite, "3 Progression", preuve("ad", int(r.ligne_succes)),
                f"Connexion RÉUSSIE de {r.utilisateur} depuis {r.source} (type {int(r.type_connexion)} = bureau à distance) juste après la rafale"))
            for _, s in r.suite_ad.iterrows():
                txt = {4672: f"Privilèges spéciaux attribués à {s.utilisateur}",
                       4720: f"Création du compte {s.compte_cree} par {s.utilisateur}",
                       4728: f"{s.compte_ajoute} ajouté au groupe « {s.groupe} » par {s.utilisateur}"}.get(s.event_id, s.event)
                evts.append(evenement(s.horodatage, "4 Privilèges et persistance", preuve("ad", s.ligne), txt))
    # Chaque fenetre suspecte est detaillee avec ses flux, son taux de blocage et ses ports.
    for _, s in scans.iterrows():
        fw = d["firewall"]
        flux = fw[(fw.ip_source == s.ip_source) & (fw.horodatage.dt.floor(FENETRE_SCAN) == s.fenetre)]
        note = "" if s.dans_inventaire else " (absente de l'inventaire)"
        evts.append(evenement(flux.horodatage.min(), "3 Progression", preuves("firewall", flux.ligne),
            f"Balayage interne depuis {s.ip_source}{note} : {s.flux} flux, "
            f"{s.couples} couples serveur:port, {int(s['taux_blocage_%'])} % bloqués, ports {s.ports} (jusqu'à {flux.horodatage.max():%H:%M:%S})"))
    if len(scans):
        ip_p = scans.iloc[0].ip_source
        piv = activite_pivot(d, ip_p)
        scan_fin = scans.iloc[0].fenetre + pd.Timedelta(FENETRE_SCAN)
        apres = piv[piv.horodatage >= scan_fin]
        res.update(ip_pivot=ip_p, pivot_apres_scan=apres)
        for _, f in apres.iterrows():
            evts.append(evenement(f.horodatage, "3 Progression", preuve("firewall", f.ligne),
                                  f"Flux {f.action.upper()} {ip_p} → {f.serveur} ({f.ip_dest}) port {f.port_dest} (bureau à distance)"))
    # Le compte suspect est suivi dans les connexions AD reussies ulterieures.
    res["connexions_persistance"] = pd.DataFrame()
    if len(creations[creations.suspect]):
        compte = creations[creations.suspect].iloc[0].compte
        co = ad[(ad.utilisateur == compte) & (ad.event_id == 4624)]
        res["connexions_persistance"] = co
        for _, x in co.iterrows():
            evts.append(evenement(x.horodatage, "4 Privilèges et persistance", preuve("ad", x.ligne),
                                  f"Connexion de {compte} sur {x.machine_cible} depuis {x.ip_source} (type {int(x.type_connexion)})"))
    # A defaut d'IP fournie, la premiere source non interne d'une rafale sert de candidat externe.
    if ip_ext is None:
        externes = rafales[~rafales.source.map(est_interne)] if len(rafales) else rafales
        ip_ext = externes.source.iloc[0] if len(externes) else None
    res["ip_externe"] = ip_ext
    # La comparaison VPN est lancee seulement si l'IP externe et le pivot sont connus.
    if ip_ext and "ip_pivot" in res:
        res["couv_ad"], res["couv_fw"] = couverture_vpn(d, ip_ext, res["ip_pivot"])
    return res, evts


def main():
    # Le rapport console rassemble les detections et les pistes de corroboration de chaque etape.
    d = charger(lire_args(__doc__).donnees)
    r, _ = analyser(d)
    # Le premier bloc detaille les episodes d'echecs et les evenements AD qui les suivent.
    titre(f"3a. Rafales d'échecs d'authentification (>= {SEUIL_ECHECS} échecs, écart < 10 min)")
    montrer(r["rafales"], ["utilisateur", "source", "debut", "fin", "nb_echecs", "motif", "serveurs", "lignes_echecs", "succes_ensuite", "type_connexion"])
    print("\nSuite immédiate dans l'AD (même compte, même source, dans l'heure) :")
    for _, x in r["rafales"].iterrows():
        if len(x.suite_ad):
            montrer(x.suite_ad, ["ligne", "horodatage", "event_id", "event", "utilisateur", "compte_cree", "compte_ajoute", "groupe"])
        else:
            print(f"  {x.utilisateur} : aucun événement ultérieur depuis {x.source} (échecs = « accès refusé » : le mot de passe était valable)")
    # Le deuxieme bloc compare le balayage detecte au maximum observe sous le seuil.
    titre("3b. Balayage interne : >= 10 couples (serveur, port) dans la même minute")
    print(f"Maximum « normal » observé : {r['scan_normal_max']} couples/minute/source ; blocage de référence : {r['taux_blocage_base']:.1f} %")
    montrer(r["scans"], ["ip_source", "fenetre", "couples", "flux", "taux_blocage_%", "ports", "dans_inventaire", "premiere", "derniere"])
    if "pivot_apres_scan" in r:
        print(f"\nActivité ultérieure de {r['ip_pivot']} (hors balayage) : {len(r['pivot_apres_scan'])} flux, tous vers :")
        print(r["pivot_apres_scan"].groupby(["serveur", "port_dest", "action"]).size().to_string())
    # Le troisieme bloc classe les creations selon le groupe obtenu, l'horaire et la source.
    titre("3c. Créations de comptes : suspect = ajouté à un groupe admin ET (nuit OU source externe)")
    montrer(r["creations"], ["ligne", "horodatage", "compte", "cree_par", "depuis", "nuit(22h-6h)", "week-end", "source_externe", "groupe_admin", "connexions_ensuite", "suspect"])
    ecartees = r["creations"][~r["creations"].suspect]
    print(f"\nÉcartées ({len(ecartees)}) : créées de jour, depuis le réseau interne, sans ajout à un groupe, jamais utilisées.")
    doublons = ecartees[ecartees.compte.duplicated(keep=False)]
    inconnus = set(ecartees.cree_par) - set(d["inventaire"].proprietaire.dropna())
    print("Réserves à signaler :")
    if len(doublons):
        print(f"  - compte créé plusieurs fois : {sorted(set(doublons.compte))} (lignes {list(doublons.ligne)})")
    if ecartees["week-end"].any():
        print(f"  - créations un week-end : lignes {list(ecartees[ecartees['week-end']].ligne)}")
    if inconnus:
        print(f"  - émetteur(s) {sorted(inconnus)} et source(s) {sorted(set(ecartees.depuis))} absents de l'inventaire")
    if len(r["connexions_persistance"]):
        titre("3d. Utilisation du compte de persistance")
        montrer(r["connexions_persistance"], ["ligne", "horodatage", "utilisateur", "machine_cible", "ip_source", "type_connexion"])
    if "couv_ad" in r:
        titre(f"3e. Cohérence : l'activité de l'attaquant est-elle couverte par une session VPN journalisée ({r['ip_externe']}) ?")
        a, f = r["couv_ad"], r["couv_fw"]
        print(f"  événements AD venant de {r['ip_externe']}      : {int(a.dans_session.sum())}/{len(a)} dans une session VPN")
        print(f"  flux pare-feu de {r['ip_pivot']} (hors balayage) : {int(f.dans_session.sum())}/{len(f)} dans une session VPN")
        print("  Hors session :")
        montrer(a[~a.dans_session], ["ligne", "horodatage", "utilisateur", "machine_cible", "event_id"])
        print("  → soit la journalisation VPN est incomplète, soit l'attaquant dispose d'un accès non journalisé (hypothèse à ne pas affirmer).")


if __name__ == "__main__":
    main()
