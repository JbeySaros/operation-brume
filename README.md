# Opération Brume — jeu de données d'investigation (fictif)

Projet du cours **PYS-701 — Programmation Python pour la sécurité** (M1 ACR).

Vous êtes analyste au SOC de **Nordis Logistique**, une entreprise de transport
fictive (~300 postes, 3 sites : Rouen, Lyon, Lille). Un lundi matin, plusieurs
serveurs de fichiers sont devenus inaccessibles. La direction veut savoir ce qui
s'est passé. On vous remet les journaux des **3 dernières semaines**.

**Votre mission : reconstituer l'attaque à partir de ces journaux, en écrivant
vos propres scripts Python.**

> ⚠️ **Données entièrement fictives.** Aucune information réelle. Les adresses IP
> externes appartiennent aux plages réservées à la documentation
> (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) et les domaines se
> terminent par `.example`. Les fichiers ne contiennent **que des traces de
> journaux** : aucun code malveillant, aucune pièce jointe réelle.

## Contenu

| Fichier | Format | Source simulée |
|---|---|---|
| `donnees/vpn_auth.csv` | CSV | Connexions au VPN (utilisateur, IP, pays, résultat) |
| `donnees/ad_events.jsonl` | JSON Lines | Journal d'authentification Windows (4624, 4625, 4720, 4728…) |
| `donnees/proxy_web.csv` | CSV | Navigation web sortante (hôte, URL, octets envoyés/reçus) |
| `donnees/firewall.csv` | CSV | Flux réseau autorisés et bloqués |
| `donnees/mail_gateway.csv` | CSV | Journal de la passerelle de messagerie |
| `donnees/edr_alerts.json` | JSON | Alertes de l'antivirus d'entreprise (EDR) |
| `donnees/inventaire_parc.csv` | CSV | Inventaire des postes et serveurs (pour relier IP ↔ machines ↔ utilisateurs) |

Les fichiers sont **cohérents entre eux** : un même utilisateur, une même adresse
et un même horaire se retrouvent dans plusieurs sources. Il faut **croiser** les
sources pour reconstituer l'histoire. Le volume (dizaines de milliers de lignes)
interdit l'analyse à la main : c'est tout l'intérêt de Python.

## Pour commencer

```bash
python3 -m venv .venv && source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install pandas
python3 demarrage.py --donnees ./donnees
```

`demarrage.py` charge les sept sources avec pandas et affiche quelques repères.
Il ne contient **aucune réponse** : à vous de l'étendre.

## Ce que vous devez produire

1. **Vos scripts Python** d'analyse (pandas autorisé), lisibles et commentés.
2. **Une chronologie horodatée** de l'attaque : pour chaque étape, la preuve
   tirée des journaux (fichier, ligne, champ).
3. **Les indicateurs de compromission** : comptes, adresses IP, domaines,
   machines touchées.
4. **Une estimation** du volume de données sorties et du périmètre impacté.
5. **Des recommandations** : règles de détection à ajouter, mesures correctives.
6. Le tout présenté dans un **dossier** et une **soutenance** (voir la page du
   projet dans le cours).

## Pistes de départ

Sans tout dévoiler, voici le genre de questions qui font avancer :

- Y a-t-il des connexions VPN **réussies depuis un pays inhabituel** ?
- Un compte a-t-il subi une **rafale d'échecs d'authentification** suivie d'un
  **succès** depuis la même adresse ?
- Un **compte** a-t-il été **créé** puis **ajouté à un groupe d'administration**,
  et à quelle heure ?
- Quel hôte externe a reçu le plus **d'octets envoyés**, et quand ?
- Une **adresse IP absente de l'inventaire** apparaît-elle dans le pare-feu ?
- Un **courriel** au score de risque juste sous le seuil de blocage est-il passé ?
- Quelles **alertes EDR critiques** sont restées « ouvertes » ?

Bon courage, analyste. 🕵️

---

*Données générées pour un usage pédagogique. Toute ressemblance avec une
organisation ou une personne réelle serait fortuite.*
