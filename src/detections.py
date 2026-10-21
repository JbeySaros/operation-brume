"""Règles de détection : définition, rétro-test sur les 3 semaines, marge des seuils, chasse.

    python3 src/detections.py --donnees donnees [--sorties sorties]

Pour chaque règle on mesure, en rejouant les journaux :
  1. le nombre d'alertes sur 21 jours, dont combien sont rattachées à l'attaque ;
  2. l'heure du premier déclenchement utile, donc l'AVANCE sur l'exfiltration
     (19/09) et sur le chiffrement (20/09) ;
  3. la marge sur le seuil : jusqu'où le durcir ou l'assouplir sans faux positif.
Chaque règle existe en variantes : « stricte » (celle des scripts), « large »
(seuil assoupli, pour chasser d'autres compromissions) et « naïve » (règle
simpliste, pour montrer pourquoi elle est inutilisable).

Les alertes NON rattachées à l'attaque sont listées : ce sont les pistes à
qualifier pour savoir s'il existe d'autres compromissions.
"""
import argparse
from pathlib import Path

import pandas as pd

import entree
import impact
import progression
from chargement import charger, est_interne, montrer, preuve, titre

COLONNES = ["horodatage", "acteurs", "preuve", "detail"]


# --------------------------------------------------------------------------- #
# Contexte : ce que l'on sait de l'attaque (dérivé des analyses, rien en dur)
# --------------------------------------------------------------------------- #
def contexte(d):
    e, _ = entree.analyser(d)
    p, _ = progression.analyser(d, e.get("ip_attaquant"))
    i, _ = impact.analyser(d, e.get("ip_attaquant"), p.get("pivot_apres_scan"))
    susp = p["creations"][p["creations"].suspect]
    ouvertes = i["alertes_ouvertes"]
    comptes = {e["victime"]} | set(susp.compte)
    comptes |= {r.utilisateur for _, r in p["rafales"].iterrows() if pd.notna(r.succes_ensuite)}
    return {
        "comptes": comptes,
        "ips": {e["ip_attaquant"], p.get("ip_pivot")} - {None},
        "domaines": {e["domaine_hameconnage"]} | set(i["transferts"].host),
        "transferts": d["proxy"][d["proxy"].host.isin(set(i["transferts"].host))],
        "ref": {"debut": e["mail"].horodatage,
                "compromission_privilegiee": susp.horodatage.min(),
                "exfiltration": i["transferts"].debut.min(),
                "chiffrement": ouvertes[ouvertes.titre.str.contains("rançongiciel")].horodatage.min(),
                "fin": ouvertes.horodatage.max()}}


def rattachee(alerte, ctx):
    """Alerte liée à l'attaque : IP / domaine connu, ou compte compromis PENDANT l'attaque."""
    ac = set(alerte["acteurs"])
    if ac & (ctx["ips"] | ctx["domaines"]):
        return True
    r = ctx["ref"]
    return bool(ac & ctx["comptes"]) and r["debut"] <= alerte["horodatage"] <= r["fin"]


def _a(ts, acteurs, preuve_txt, detail):
    return {"horodatage": ts, "acteurs": [a for a in acteurs if isinstance(a, str)],
            "preuve": preuve_txt, "detail": detail}


def _df(lignes):
    return pd.DataFrame(lignes, columns=COLONNES).sort_values("horodatage").reset_index(drop=True) if lignes \
        else pd.DataFrame(columns=COLONNES)


# --------------------------------------------------------------------------- #
# Règles : chacune prend les données + un paramètre et renvoie ses alertes
# --------------------------------------------------------------------------- #
def r_mail_indices(d, min_indices=2):
    """Mail livré cumulant des indices : domaine sosie, double extension, lien, score limite."""
    s, _ = entree.courriel_piege(d, min_indices)
    return _df([_a(r.horodatage, [r.destinataire.split("@")[0], r.domaine], preuve("mail", r.ligne),
                   f"{r.nb_indices} indice(s), score {r.score_risque}") for _, r in s.iterrows()])


def r_mail_score(d, seuil=30):
    """Naïve : tout mail livré dont le score atteint un seuil."""
    m = d["mail"]
    m = m[(m.verdict == "livre") & (m.score_risque >= seuil)]
    return _df([_a(r.horodatage, [r.destinataire.split("@")[0], r.expediteur.split("@")[1]],
                   preuve("mail", r.ligne), f"score {r.score_risque}") for _, r in m.iterrows()])


def r_proxy_nouvel_hote(d, avec_post=True, jours_ref=3, max_comptes=5):
    """Hôte jamais vu pendant les premiers jours, peu de comptes, (avec envoi de formulaire)."""
    p = d["proxy"]
    premier, nb = p.groupby("host").horodatage.min(), p.groupby("host").login.nunique()
    nouveaux = [h for h in premier.index if premier[h] > p.horodatage.min() + pd.Timedelta(days=jours_ref) and nb[h] <= max_comptes]
    x = p[p.host.isin(nouveaux)]
    if avec_post:
        x = x[x.methode == "POST"]
    x = x.sort_values("horodatage").drop_duplicates(["login", "host"])
    return _df([_a(r.horodatage, [r.login, r.host], preuve("proxy", r.ligne),
                   f"{r.methode} sur un hôte nouveau ({nb[r.host]} compte(s) sur la période)") for _, r in x.iterrows()])


def r_proxy_volume(d, seuil_octets=50e6):
    """Octets envoyés par (compte, hôte) en une heure au-delà d'un seuil."""
    p = d["proxy"].sort_values("horodatage").copy()
    p["h"] = p.horodatage.dt.floor("h")
    p["cumul"] = p.groupby(["login", "host", "h"]).octets_envoyes.cumsum()
    x = p[p.cumul >= seuil_octets].drop_duplicates(["login", "host", "h"])
    return _df([_a(r.horodatage, [r.login, r.host], preuve("proxy", r.ligne),
                   f"{r.cumul / 1e6:.1f} Mo envoyés en 1 h vers {r.host}") for _, r in x.iterrows()])


def r_edr_ouverte(d, critique_seulement=True):
    e = d["edr"][d["edr"].statut == "ouvert"]
    if critique_seulement:
        e = e[e.gravite == "critique"]
    return _df([_a(r.horodatage, [r.utilisateur, r.machine], preuve("edr", r.id), f"{r.titre} ({r.gravite})") for _, r in e.iterrows()])


def r_edr_nuit(d):
    """Toute alerte EDR entre 22h et 6h (aucun faux positif observé la nuit)."""
    e = d["edr"]
    e = e[(e.horodatage.dt.hour >= 22) | (e.horodatage.dt.hour < 6)]
    return _df([_a(r.horodatage, [r.utilisateur, r.machine], preuve("edr", r.id), f"{r.titre} ({r.gravite}, {r.statut})") for _, r in e.iterrows()])


def r_vpn_mfa(d, fenetre="5min"):
    """Échec « second facteur manquant » suivi d'un succès (même compte, même IP)."""
    v, out = d["vpn"].sort_values("horodatage"), []
    for _, e in v[v.motif == "second facteur manquant"].iterrows():
        ok = v[(v.login == e.login) & (v.ip_source == e.ip_source) & (v.resultat == "succes")
               & (v.horodatage > e.horodatage) & (v.horodatage <= e.horodatage + pd.Timedelta(fenetre))]
        if len(ok):
            x = ok.iloc[0]
            out.append(_a(x.horodatage, [x.login, x.ip_source], preuve("vpn", x.ligne), "succès après échec du second facteur"))
    return _df(out)


def r_vpn_voyage(d, fenetre="10min"):
    """Même compte vu dans deux pays différents à moins de 10 min : déplacement impossible."""
    out = []
    for u, g in d["vpn"].sort_values("horodatage").groupby("login"):
        g = g.reset_index(drop=True)
        for i in range(1, len(g)):
            if g.pays[i] != g.pays[i - 1] and g.horodatage[i] - g.horodatage[i - 1] <= pd.Timedelta(fenetre):
                out.append(_a(g.horodatage[i], [u, g.ip_source[i]], preuve("vpn", g.ligne[i]), f"{g.pays[i - 1]} → {g.pays[i]} en peu de temps"))
    return _df(out)


def r_vpn_pays(d):
    """Connexion depuis un pays autre que le pays habituel du compte (mode)."""
    v = d["vpn"].copy()
    v["usuel"] = v.login.map(v.groupby("login").pays.agg(lambda s: s.mode().iloc[0]))
    x = v[v.pays != v.usuel]
    return _df([_a(r.horodatage, [r.login, r.ip_source], preuve("vpn", r.ligne), f"{r.resultat} depuis {r.pays} (habituel : {r.usuel})") for _, r in x.iterrows()])


def r_vpn_ip_nouvelle(d):
    """Naïve : succès depuis une IP jamais vue pour ce compte (hors première connexion)."""
    out = []
    for u, g in d["vpn"][d["vpn"].resultat == "succes"].sort_values("horodatage").groupby("login"):
        vues = set()
        for _, r in g.iterrows():
            if vues and r.ip_source not in vues:
                out.append(_a(r.horodatage, [u, r.ip_source], preuve("vpn", r.ligne), "IP jamais vue pour ce compte"))
            vues.add(r.ip_source)
    return _df(out)


def r_ad_source(d, hors_inventaire=False):
    """Authentification AD dont la source n'est pas un poste du parc (IP externe ou, en large, inconnue)."""
    ad, inv = d["ad"], d["inventaire"]
    connu = set(inv.hostname) | set(inv.ip)
    x = ad[~ad.ip_source.isin(connu)] if hors_inventaire else ad[~ad.ip_source.map(est_interne)]
    return _df([_a(r.horodatage, [r.utilisateur, r.ip_source, r.compte_cree], preuve("ad", r.ligne), f"{r.event} depuis {r.ip_source}") for _, r in x.iterrows()])


def r_ad_rafale(d, seuil=5, fenetre="10min", cumul=False):
    """>= seuil échecs d'un compte en moins de `fenetre` d'écart ; en « cumul » : total sur 3 semaines."""
    f = d["ad"][d["ad"].event_id == 4625].sort_values("horodatage")
    out = []
    for cle, g in f.groupby("utilisateur" if cumul else ["utilisateur", "ip_source"]):
        g = g.reset_index(drop=True)
        episodes = [g] if cumul else [e for _, e in g.groupby((g.horodatage.diff() > pd.Timedelta(fenetre)).cumsum())]
        for e in episodes:
            if len(e) >= seuil:
                x = e.iloc[seuil - 1]
                out.append(_a(x.horodatage, [x.utilisateur, x.ip_source], preuve("ad", x.ligne), f"{seuil}e échec ({len(e)} dans l'épisode)"))
    return _df(out)


def r_ad_sondage(d, seuil=3, fenetre="15min"):
    """Un compte qui essuie des refus sur >= seuil serveurs différents en peu de temps."""
    f = d["ad"][d["ad"].event_id == 4625].sort_values("horodatage")
    out = []
    for _, g in f.groupby(["utilisateur", "ip_source"]):
        g = g.reset_index(drop=True)
        for _, e in g.groupby((g.horodatage.diff() > pd.Timedelta(fenetre)).cumsum()):
            cum = (~e.machine_cible.duplicated()).astype(int).cumsum()
            if cum.max() >= seuil:
                x = e[cum >= seuil].iloc[0]
                out.append(_a(x.horodatage, [x.utilisateur, x.ip_source], preuve("ad", x.ligne), f"refus sur {seuil} serveurs différents"))
    return _df(out)


def r_ad_rdp(d):
    """Ouverture de session de type 10 (bureau à distance) : une seule sur 3 semaines."""
    x = d["ad"][(d["ad"].event_id == 4624) & (d["ad"].type_connexion == 10)]
    return _df([_a(r.horodatage, [r.utilisateur, r.ip_source], preuve("ad", r.ligne), f"RDP sur {r.machine_cible}") for _, r in x.iterrows()])


def r_ad_escalade(d, toute_creation=False):
    """Privilèges spéciaux (4672) + création (4720) + ajout à un groupe (4728), même compte et source, en 1 h."""
    ad, out = d["ad"].sort_values("horodatage"), []
    if toute_creation:
        for _, r in ad[ad.event_id == 4720].iterrows():
            out.append(_a(r.horodatage, [r.utilisateur, r.ip_source, r.compte_cree], preuve("ad", r.ligne), f"création de {r.compte_cree}"))
        return _df(out)
    for _, r in ad[ad.event_id == 4728].iterrows():
        h = ad[(ad.utilisateur == r.utilisateur) & (ad.ip_source == r.ip_source) & (ad.horodatage <= r.horodatage)
               & (ad.horodatage >= r.horodatage - pd.Timedelta("1h"))]
        if {4672, 4720} <= set(h.event_id):
            out.append(_a(r.horodatage, [r.utilisateur, r.ip_source, r.compte_ajoute], preuve("ad", r.ligne), f"{r.compte_ajoute} ajouté à {r.groupe}"))
    return _df(out)


def r_fw_balayage(d, seuil=10):
    """>= seuil couples (serveur:port) distincts depuis une même source dans la même minute."""
    fw = d["firewall"].sort_values("horodatage").copy()
    fw["fen"] = fw.horodatage.dt.floor("1min")
    fw["couple"] = fw.ip_dest + ":" + fw.port_dest.astype(str)
    nouveau = (~fw.duplicated(["ip_source", "fen", "couple"])).astype(int)
    fw["cum"] = nouveau.groupby([fw.ip_source, fw.fen]).cumsum()
    x = fw[fw.cum >= seuil].drop_duplicates(["ip_source", "fen"])
    return _df([_a(r.horodatage, [r.ip_source], preuve("firewall", r.ligne), f"{seuil} couples serveur:port en 1 min") for _, r in x.iterrows()])


def r_fw_port_rare(d, part_max=0.01):
    """Flux sur un port utilisé par moins de 1 % des sources (ici : SSH)."""
    fw = d["firewall"]
    part = fw.groupby("port_dest").ip_source.nunique() / fw.ip_source.nunique()
    x = fw[fw.port_dest.isin(part[part < part_max].index)].sort_values("horodatage").drop_duplicates("ip_source")
    return _df([_a(r.horodatage, [r.ip_source], preuve("firewall", r.ligne), f"port {r.port_dest} quasi jamais utilisé") for _, r in x.iterrows()])


def r_fw_hors_inventaire(d):
    """Première apparition d'une IP source absente de l'inventaire."""
    fw = d["firewall"]
    x = fw[~fw.ip_source.isin(d["inventaire"].ip)].sort_values("horodatage").drop_duplicates("ip_source")
    return _df([_a(r.horodatage, [r.ip_source], preuve("firewall", r.ligne), "IP absente de l'inventaire") for _, r in x.iterrows()])


# Catalogue : (code, nom, source, variante, fonction)
REGLES = [
    ("R01", "Courriel piégé livré", "mail", "stricte", lambda d: r_mail_indices(d, 2)),
    ("R01", "Courriel piégé livré", "mail", "large", lambda d: r_mail_indices(d, 1)),
    ("R01", "Courriel piégé livré", "mail", "naïve", lambda d: r_mail_score(d, 30)),
    ("R02", "Hôte web nouveau + formulaire", "proxy", "stricte", lambda d: r_proxy_nouvel_hote(d, True)),
    ("R02", "Hôte web nouveau + formulaire", "proxy", "large", lambda d: r_proxy_nouvel_hote(d, False)),
    ("R03", "Alerte EDR critique non close", "edr", "stricte", lambda d: r_edr_ouverte(d, True)),
    ("R03", "Alerte EDR critique non close", "edr", "large", lambda d: r_edr_ouverte(d, False)),
    ("R04", "Alerte EDR nocturne (22h-6h)", "edr", "stricte", r_edr_nuit),
    ("R05", "VPN : succès après échec du 2e facteur", "vpn", "stricte", r_vpn_mfa),
    ("R06", "VPN : déplacement impossible", "vpn", "stricte", r_vpn_voyage),
    ("R06", "VPN : pays inhabituel pour le compte", "vpn", "large", r_vpn_pays),
    ("R06", "VPN : IP jamais vue pour le compte", "vpn", "naïve", r_vpn_ip_nouvelle),
    ("R07", "AD : source hors parc (IP externe)", "ad", "stricte", lambda d: r_ad_source(d, False)),
    ("R07", "AD : source absente de l'inventaire", "ad", "large", lambda d: r_ad_source(d, True)),
    ("R08", "AD : refus sur plusieurs serveurs", "ad", "stricte", lambda d: r_ad_sondage(d, 3)),
    ("R08", "AD : refus sur plusieurs serveurs", "ad", "large", lambda d: r_ad_sondage(d, 2)),
    ("R09", "AD : rafale d'échecs", "ad", "stricte", lambda d: r_ad_rafale(d, 5)),
    ("R09", "AD : rafale d'échecs", "ad", "large", lambda d: r_ad_rafale(d, 3)),
    ("R09", "AD : 5 échecs cumulés sur 3 semaines", "ad", "naïve", lambda d: r_ad_rafale(d, 5, cumul=True)),
    ("R10", "AD : session RDP (type 10)", "ad", "stricte", r_ad_rdp),
    ("R11", "AD : privilèges + création + ajout admin", "ad", "stricte", lambda d: r_ad_escalade(d, False)),
    ("R11", "AD : toute création de compte", "ad", "large", lambda d: r_ad_escalade(d, True)),
    ("R12", "Pare-feu : balayage interne", "firewall", "stricte", lambda d: r_fw_balayage(d, 10)),
    ("R12", "Pare-feu : balayage interne", "firewall", "large", lambda d: r_fw_balayage(d, 5)),
    ("R13", "Pare-feu : port quasi jamais utilisé", "firewall", "stricte", r_fw_port_rare),
    ("R14", "Pare-feu : IP absente de l'inventaire", "firewall", "stricte", r_fw_hors_inventaire),
    ("R15", "Proxy : envoi massif vers un hôte (> 50 Mo/h)", "proxy", "stricte", lambda d: r_proxy_volume(d, 50e6)),
    ("R15", "Proxy : envoi massif vers un hôte (> 1 Mo/h)", "proxy", "large", lambda d: r_proxy_volume(d, 1e6)),
]


def duree(td):
    if pd.isna(td):
        return "-"
    s = int(td.total_seconds())
    signe, s = ("-" if s < 0 else ""), abs(s)
    j, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    return signe + (f"{j} j " if j else "") + f"{h} h {r // 60:02d} min"


def retro_test(d, ctx):
    """Rejoue toutes les règles ; renvoie le tableau de synthèse et les alertes de chacune."""
    lignes, alertes, ref = [], {}, ctx["ref"]
    tr = ctx["transferts"]
    for code, nom, src, var, f in REGLES:
        a = f(d)
        a["rattachee"] = [rattachee(r, ctx) for _, r in a.iterrows()] if len(a) else []
        alertes[(code, var)] = a
        tp = a[a.rattachee] if len(a) else a
        t0 = tp.horodatage.min() if len(tp) else pd.NaT
        sorti = tr[tr.horodatage <= t0].octets_envoyes.sum() / 1e6 if pd.notna(t0) else float("nan")
        lignes.append({"code": code, "regle": nom, "variante": var, "alertes": len(a), "rattachees": len(tp),
                       "faux_positifs": len(a) - len(tp), "premiere_alerte_utile": t0,
                       "avance_sur_exfiltration": (ref["exfiltration"] - t0) if pd.notna(t0) else pd.NaT,
                       "avance_sur_chiffrement": (ref["chiffrement"] - t0) if pd.notna(t0) else pd.NaT,
                       "Mo_deja_sortis": round(sorti, 0)})
    return pd.DataFrame(lignes), alertes


def sensibilite(d, ctx):
    """Fait varier le seuil des règles numériques : quelle plage détecte sans faux positif ?"""
    tr = ctx["transferts"]
    jeux = [("Rafale d'échecs AD (échecs en 10 min)", list(range(2, 11)), lambda k: r_ad_rafale(d, k)),
            ("Balayage pare-feu (couples serveur:port/min)", [3, 4, 5, 6, 8, 10, 15, 20, 30, 40], lambda k: r_fw_balayage(d, k)),
            ("Volume envoyé vers un hôte (octets/heure)", [1e3, 1e4, 1e5, 1e6, 1e7, 5e7, 1e8, 5e8, 1e9], lambda k: r_proxy_volume(d, k)),
            ("Mail livré : score minimal", [20, 30, 40, 50, 55, 58, 59], lambda k: r_mail_score(d, k))]
    out = []
    for nom, seuils, f in jeux:
        for k in seuils:
            a = f(k)
            rat = [rattachee(r, ctx) for _, r in a.iterrows()] if len(a) else []
            t0 = a[rat].horodatage.min() if any(rat) else pd.NaT
            out.append({"regle": nom, "seuil": k, "alertes": len(a), "faux_positifs": len(a) - sum(rat),
                        "detectee": bool(any(rat)), "premiere_alerte_utile": t0,
                        "Mo_deja_sortis": round(tr[tr.horodatage <= t0].octets_envoyes.sum() / 1e6, 0) if pd.notna(t0) else float("nan")})
    return pd.DataFrame(out)


def pistes(alertes):
    """Alertes NON rattachées des variantes stricte/large, regroupées par acteurs : pistes à qualifier."""
    lignes = []
    for (code, var), a in alertes.items():
        if var == "naïve" or not len(a):
            continue
        for _, r in a[~a.rattachee].iterrows():
            lignes.append({"acteurs": " / ".join(r.acteurs), "regle": f"{code} {var}", "horodatage": r.horodatage, "preuve": r.preuve})
    if not lignes:
        return pd.DataFrame(columns=["acteurs", "regles", "evenements", "du", "au", "preuves"])
    t = pd.DataFrame(lignes)
    return t.groupby("acteurs").agg(regles=("regle", lambda s: ", ".join(sorted(set(s)))), evenements=("preuve", "nunique"),
                                    du=("horodatage", "min"), au=("horodatage", "max"),
                                    preuves=("preuve", lambda s: ", ".join(sorted(set(s))[:4]))).reset_index()


NOTES_ATTENDUES = {"PsExec utilisé par l'IT": {"it"}, "Tâche de maintenance planifiée": {"it"},
                   "Export comptable mensuel": {"compta"}}


def audit_clotures(d, ctx):
    """Les alertes EDR closes « faux positif » sont-elles justifiées par un motif cohérent avec le service ?"""
    inv = d["inventaire"]
    service = inv[inv.type == "poste"].set_index("proprietaire").service
    fp = d["edr"][d["edr"].statut == "clos_faux_positif"].copy()
    fp["service"] = fp.utilisateur.map(service)
    lignes = []
    for note, g in fp.groupby("note_analyste"):
        attendu = NOTES_ATTENDUES.get(note)
        coh = int(g.service.isin(attendu).sum()) if attendu else None
        lignes.append({"motif_de_cloture": note, "alertes": len(g), "attendu": "/".join(sorted(attendu)) if attendu else "(non précisé)",
                       "coherentes": coh if coh is not None else "-", "incoherentes": len(g) - coh if coh is not None else "-"})
    r = ctx["ref"]
    apres = fp[fp.utilisateur.isin(ctx["comptes"]) & (fp.horodatage >= r["debut"])]
    return pd.DataFrame(lignes), apres


def presence(d, compte):
    """Où un compte apparaît-il ? (permet de juger si une piste est isolée ou corroborée)."""
    ad = d["ad"]
    return {"AD : authentifications réussies (4624)": int(((ad.utilisateur == compte) & (ad.event_id == 4624)).sum()),
            "AD : échecs (4625)": int(((ad.utilisateur == compte) & (ad.event_id == 4625)).sum()),
            "AD : autres évènements": int(((ad.utilisateur == compte) & ~ad.event_id.isin([4624, 4625])).sum()),
            "VPN": int((d["vpn"].login == compte).sum()), "proxy": int((d["proxy"].login == compte).sum()),
            "courriels reçus": int(d["mail"].destinataire.str.startswith(compte + "@").sum()),
            "alertes EDR": int((d["edr"].utilisateur == compte).sum()),
            "dans l'inventaire (propriétaire)": bool((d["inventaire"].proprietaire == compte).any())}


def plage_sure(t):
    ok = t[(t.faux_positifs == 0) & t.detectee]
    return ok.groupby("regle").seuil.agg(["min", "max"]) if len(ok) else pd.DataFrame()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--donnees", type=Path, default=Path("donnees"))
    ap.add_argument("--sorties", type=Path, default=Path("sorties"))
    a = ap.parse_args()
    d = charger(a.donnees)
    ctx = contexte(d)
    ref = ctx["ref"]
    synth, alertes = retro_test(d, ctx)
    sens = sensibilite(d, ctx)
    p = pistes(alertes)
    clot, apres = audit_clotures(d, ctx)

    titre("Repères de l'attaque (dérivés des analyses)")
    for k, v in ref.items():
        print(f"  {k:28} {v:%Y-%m-%d %H:%M:%S}")
    titre("1. Rétro-test : chaque règle rejouée sur les 3 semaines")
    aff = synth.copy()
    for c in ["premiere_alerte_utile"]:
        aff[c] = aff[c].map(lambda t: "-" if pd.isna(t) else f"{t:%d/%m %H:%M:%S}")
    for c in ["avance_sur_exfiltration", "avance_sur_chiffrement"]:
        aff[c] = aff[c].map(duree)
    montrer(aff)
    print("\nLecture : « avance » = délai entre la 1re alerte utile et l'exfiltration (19/09 03:37) / le chiffrement (20/09 05:25) ;")
    print("négatif = l'alerte arrive APRÈS le début. Mo_deja_sortis = volume parti avant l'alerte.")

    titre("2. Marge des seuils : plage sans faux positif qui détecte encore l'attaque")
    t = sens.copy()
    t["premiere_alerte_utile"] = t.premiere_alerte_utile.map(lambda x: "-" if pd.isna(x) else f"{x:%d/%m %H:%M:%S}")
    montrer(t)
    print()
    montrer(plage_sure(sens).reset_index().rename(columns={"min": "seuil_min_sans_FP", "max": "seuil_max_qui_detecte"}))

    titre("3. Chasse : alertes des variantes stricte/large NON rattachées à l'attaque (pistes à qualifier)")
    if p.empty:
        print("  aucune")
    else:
        pd.set_option("display.max_colwidth", 90)
        montrer(p)
        for c in sorted({x.split(" / ")[0] for x in p.acteurs}):
            print(f"\nPrésence de « {c} » dans les sources : {presence(d, c)}")
        print("→ aucune de ces pistes ne touche l'IP, les domaines ou les comptes de l'attaque ; à qualifier hors journaux (RH, inventaire).")
    titre("4. Audit des clôtures EDR : le motif de clôture est-il cohérent avec le service de l'utilisateur ?")
    montrer(clot)
    print(f"\nAlertes « faux positif » sur les comptes compromis APRÈS le début de l'attaque : {len(apres)}")
    if len(apres):
        montrer(apres, ["ligne", "horodatage", "machine", "utilisateur", "titre", "note_analyste"])

    a.sorties.mkdir(exist_ok=True)
    o = synth.copy()
    o["premiere_alerte_utile"] = o.premiere_alerte_utile.map(lambda t: "" if pd.isna(t) else t.strftime("%Y-%m-%d %H:%M:%S%z"))
    for c in ["avance_sur_exfiltration", "avance_sur_chiffrement"]:
        o[c] = o[c].map(lambda x: "" if pd.isna(x) else duree(x))
    o.to_csv(a.sorties / "regles.csv", index=False, encoding="utf-8")
    s2 = sens.copy()
    s2["premiere_alerte_utile"] = s2.premiere_alerte_utile.map(lambda x: "" if pd.isna(x) else x.strftime("%Y-%m-%d %H:%M:%S%z"))
    s2.to_csv(a.sorties / "seuils.csv", index=False, encoding="utf-8")
    print(f"\nÉcrits : {a.sorties / 'regles.csv'}, {a.sorties / 'seuils.csv'}")


if __name__ == "__main__":
    main()
