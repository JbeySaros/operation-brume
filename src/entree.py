"""Niveaux 2 - Trouver le point d'entree : courriel piege, clic, acces VPN.

    python3 src/entree.py --donnees donnees

Methode : on part des indices forts de CHAQUE source puis on les recoupe.
Rien n'est code en dur (ni compte, ni IP) : tout est derive des donnees.
"""
import difflib
from urllib.parse import urlparse

import pandas as pd

from chargement import (charger, evenement, lire_args, montrer, preuve, preuves,
                        titre)

MARGE_SEUIL = 15      # un mail livre a moins de 15 points du seuil de blocage est « limite »
MIN_MAILS_USUEL = 50  # un domaine expediteur « habituel » envoie au moins 50 mails


def courriel_piege(d, min_indices=2):
    """Mails LIVRES cumulant des indices de piege (>= min_indices, 2 par defaut)."""
    ml = d["mail"].copy()
    # Le seuil de blocage n'est pas documente : on l'encadre par les donnees.
    max_livre = int(ml.loc[ml.verdict == "livre", "score_risque"].max())
    min_spam = int(ml.loc[ml.verdict == "spam", "score_risque"].min())
    ml["domaine"] = ml.expediteur.str.split("@").str[1]
    freq = ml.domaine.value_counts()
    usuels = list(freq[freq >= MIN_MAILS_USUEL].index)

    def sosie(dom):  # domaine proche d'un domaine habituel sans etre identique
        if dom in usuels:
            return None
        proche = difflib.get_close_matches(dom, usuels, n=1, cutoff=0.9)
        return proche[0] if proche else None

    livres = ml[ml.verdict == "livre"].copy()
    livres["sosie_de"] = livres.domaine.map(sosie)
    livres["double_extension"] = livres.piece_jointe.fillna("").str.contains(
        r"\.(?:pdf|docx?|xlsx?)\.(?:htm|html|exe|js|zip|scr)$", case=False, regex=True)
    livres["avec_lien"] = livres.lien.notna()
    livres["score_limite"] = livres.score_risque >= min_spam - MARGE_SEUIL
    livres["nb_indices"] = (livres.sosie_de.notna().astype(int) + livres.double_extension.astype(int)
                            + livres.avec_lien.astype(int) + livres.score_limite.astype(int))
    suspects = livres[livres.nb_indices >= min_indices]
    top = livres.nlargest(3, "score_risque")[["ligne", "score_risque", "expediteur"]]
    return suspects, {"max_livre": max_livre, "min_spam": min_spam, "top_scores_livres": top}


def clic_et_identifiants(d, mail):
    """Le destinataire a-t-il visite le lien ? (proxy) puis alerte EDR associee."""
    hote = urlparse(mail.lien).hostname
    victime = mail.destinataire.split("@")[0]
    p = d["proxy"]
    vis = p[(p.host == hote) & (p.login == victime) & (p.horodatage >= mail.horodatage)]
    poste = vis.ip_source.iloc[0] if len(vis) else None
    fin = vis.horodatage.max() + pd.Timedelta("30min") if len(vis) else None
    e = d["edr"]
    alertes = e[(e.machine == poste) & (e.horodatage >= mail.horodatage) & (e.horodatage <= fin)] if poste else e.iloc[0:0]
    return victime, hote, poste, vis, alertes


def acces_vpn_suspects(d, victime, apres):
    """Connexions VPN du compte victime depuis un pays inhabituel pour LUI."""
    v = d["vpn"]
    mien = v[v.login == victime]
    usuel = mien[mien.horodatage < apres].pays.mode().iloc[0]    # pays habituel avant l'incident
    susp = mien[(mien.pays != usuel) & (mien.horodatage >= apres)]
    if susp.empty:
        return usuel, susp, susp
    ip = susp.ip_source.iloc[0]
    toutes = v[v.ip_source == ip].copy()                         # tout ce que fait cette IP
    toutes["fin_session"] = toutes.horodatage + pd.to_timedelta(toutes.duree_min, unit="m")
    return usuel, susp, toutes


def analyser(d):
    res, evts = {}, []
    suspects, seuil = courriel_piege(d)
    res["seuil"], res["mails_suspects"] = seuil, suspects
    if suspects.empty:
        return res, evts
    mail = suspects.sort_values("horodatage").iloc[0]
    victime, hote, poste, vis, alertes = clic_et_identifiants(d, mail)
    res.update(victime=victime, domaine_hameconnage=hote, poste=poste, visites=vis, alertes_edr=alertes)
    usuel, susp, toutes = acces_vpn_suspects(d, victime, mail.horodatage)
    res.update(pays_usuel=usuel, vpn_suspects=susp, vpn_ip=toutes)
    res["ip_attaquant"] = toutes.ip_source.iloc[0] if len(toutes) else None
    res["mail"] = mail

    evts.append(evenement(mail.horodatage, "1 Accès initial", preuve("mail", mail.ligne),
        f"Courriel piégé livré à {victime} (score {mail.score_risque}, seuil de blocage entre "
        f"{seuil['max_livre'] + 1} et {seuil['min_spam']}) : expéditeur {mail.expediteur}, PJ {mail.piece_jointe}, lien {mail.lien}"))
    for _, r in vis.iterrows():
        txt = "envoi du formulaire (identifiants probablement saisis)" if r.methode == "POST" else "ouverture de la page"
        evts.append(evenement(r.horodatage, "1 Accès initial", preuve("proxy", r.ligne),
                              f"{victime} sur {r.ip_source} : {r.methode} {r.host}{r.url} → {txt}"))
    for _, a in alertes.iterrows():
        evts.append(evenement(a.horodatage, "1 Accès initial", preuve("edr", a.id),
                              f"Alerte EDR '{a.titre}' ({a.gravite}, statut {a.statut})"))
    for _, r in toutes.iterrows():
        if r.resultat == "echec":
            txt = f"ÉCHEC VPN {r.login} depuis {r.ip_source} ({r.pays}) : {r.motif}"
        else:
            txt = f"SUCCÈS VPN {r.login} depuis {r.ip_source} ({r.pays}), session de {r.duree_min} min (jusqu'à {r.fin_session:%d/%m %H:%M})"
        evts.append(evenement(r.horodatage, "2 Compromission du compte", preuve("vpn", r.ligne), txt))
    return res, evts


def main():
    d = charger(lire_args(__doc__).donnees)
    r, _ = analyser(d)
    s = r["seuil"]
    titre("2a. Courriel piégé : livré malgré des indices cumulés")
    print(f"Seuil de blocage non documenté : plus haut score LIVRÉ = {s['max_livre']}, plus bas score BLOQUÉ = {s['min_spam']}")
    print("3 scores les plus élevés parmi les mails livrés (le suspect est isolé ?) :")
    montrer(s["top_scores_livres"])
    montrer(r["mails_suspects"], ["ligne", "horodatage", "expediteur", "destinataire", "piece_jointe", "lien",
                                  "score_risque", "sosie_de", "double_extension", "nb_indices"])
    titre(f"2b. Clic et saisie d'identifiants : {r['victime']} sur {r['poste']}")
    montrer(r["visites"], ["ligne", "horodatage", "login", "ip_source", "methode", "host", "url", "statut", "categorie"])
    print("Alerte(s) EDR dans les 30 min suivant le clic :")
    montrer(r["alertes_edr"], ["ligne", "horodatage", "machine", "titre", "gravite", "statut"])
    titre(f"2c. VPN : connexions de {r['victime']} depuis un pays inhabituel (habituel : {r['pays_usuel']})")
    montrer(r["vpn_ip"], ["ligne", "horodatage", "login", "ip_source", "pays", "resultat", "motif", "duree_min", "fin_session"])
    t = r["vpn_ip"]
    print(f"\n> IP {r['ip_attaquant']} : {t.pays.nunique()} pays différents pour une seule IP ({', '.join(sorted(t.pays.unique()))})"
          " → géolocalisation peu fiable ou infrastructure d'anonymisation : à mentionner comme limite.")
    ok = t[t.resultat == "succes"].sort_values("horodatage")
    chev = [(a.ligne, b.ligne) for a, b in zip(ok.itertuples(), ok.iloc[1:].itertuples()) if b.horodatage < a.fin_session]
    if chev:
        print(f"> Sessions VPN simultanées pour le même compte et la même IP (lignes {chev}) : incohérence à signaler.")


if __name__ == "__main__":
    main()
