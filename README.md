# Opération Brume — investigation d'un incident de sécurité

Projet final **PYS-701 — Programmation Python pour la sécurité** M1 ASR.
Auteur : **Jb Pélissier** .

Ce dépôt contient les scripts Python qui reconstituent, à partir de sept journaux
fictifs de l'entreprise **Nordis Logistique** (~300 postes, 3 sites), une attaque
de bout en bout : hameçonnage, prise de contrôle de comptes, progression dans le
réseau, vol de données et sabotage. Chaque conclusion est rattachée à une
**preuve** (fichier, numéro de ligne, champ) et l'analyse est **rejouable** :
les mêmes commandes sur les mêmes données redonnent les mêmes résultats.

> Toutes les données sont fictives (IP en `192.0.2.0/24`, `198.51.100.0/24`,
> `203.0.113.0/24`, domaines en `.example`). Les scripts ne font qu'analyser des traces.

---

## Sommaire

1. [Installation](#1-installation)
2. [Récupérer les données](#2-récupérer-les-données)
3. [Exécuter l'analyse](#3-exécuter-lanalyse)
4. [Organisation du dépôt](#4-organisation-du-dépôt)
5. [Comment fonctionne l'analyse](#5-comment-fonctionne-lanalyse)
6. [Ce que fait chaque script](#6-ce-que-fait-chaque-script)
7. [Paramètres et seuils](#7-paramètres-et-seuils)
8. [Lire les sorties et vérifier une preuve](#8-lire-les-sorties-et-vérifier-une-preuve)
9. [Limites, incohérences et hypothèses](#9-limites-incohérences-et-hypothèses)
10. [Usage de l'IA](#10-usage-de-lia)

---

## 1. Installation

Prérequis : **Python 3.10 ou plus** et **git** (testé sous WSL/Linux avec Python 3.12).
Seule dépendance : **pandas**.

```bash
git clone https://github.com/JbeySaros/operation-brume && cd operation-brume

python3 -m venv .venv
source .venv/bin/activate          # Windows natif : .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt` ne contient que `pandas`. Les scripts ont été vérifiés avec
**pandas 2.3.3** et **pandas 3.0.2** : la chronologie produite est identique.
Ils n'utilisent aucune syntaxe réservée à Python ≥ 3.12.

Si `python3 -m venv` échoue sous Debian/Ubuntu : `sudo apt install python3-venv`.

> Avec pandas 2.3 associé à un NumPy très récent (≥ 2.5), `detections.py` peut afficher des
> `DeprecationWarning` sur les durées : sans conséquence sur les résultats (aucun avertissement avec pandas 3).

## 2. Récupérer les données

Les données (archive de 1,4 Mo, ~9 Mo décompressées) **ne sont pas versionnées** (`donnees/` est dans `.gitignore`),
conformément à l'énoncé. Elles sont fournies par l'enseignant :

- archive : <https://dafniskra.github.io/portail_cours_M1/cours/PYTHON_SECURITE/projet_donnees/operation-brume-donnees.zip>
- page du projet : <https://dafniskra.github.io/portail_cours_M1/cours/PYTHON_SECURITE/projet.html>

Copier les sept fichiers dans `donnees/` :

```
donnees/
├── vpn_auth.csv          ├── firewall.csv         ├── ad_events.jsonl
├── proxy_web.csv         ├── mail_gateway.csv     ├── edr_alerts.json
└── inventaire_parc.csv
```

> Le jeu utilisé ici compte environ **98 000 lignes** (l'énoncé annonce ~150 000) : l'énoncé précise
> que l'enseignant peut distribuer une **variante** par groupe.
> Les scripts n'écrivent en dur ni compte, ni adresse IP, ni date : ils
> redécouvrent les acteurs à partir des données (voir §5).

## 3. Exécuter l'analyse

Depuis la racine du dépôt, environnement virtuel activé. Chaque script est
autonome, s'exécute en quelques secondes et affiche ses résultats avec leurs
preuves :

```bash
python3 src/reference.py   --donnees donnees   # niveau 1 : comprendre les données, journée « normale »
python3 src/entree.py      --donnees donnees   # niveau 2 : point d'entrée (courriel, clic, VPN)
python3 src/progression.py --donnees donnees   # niveau 3 : sondage, balayage, compte privilégié, persistance
python3 src/impact.py      --donnees donnees   # niveau 4 : exfiltration, alertes EDR, périmètre
python3 src/chronologie.py --donnees donnees   # niveau 5 : frise complète + indicateurs de compromission
python3 src/detections.py  --donnees donnees   # niveau 5 : règles de détection, rétro-test, marge des seuils, chasse
```

`chronologie.py` rejoue les trois analyses précédentes et **écrit** :

- `sorties/chronologie.csv` — la frise horodatée de l'attaque, avec preuves ;
- `sorties/ioc.csv` — les indicateurs de compromission.

`detections.py` écrit de son côté :

- `sorties/regles.csv` — le rétro-test de chaque règle (alertes, faux positifs, avance sur l'attaque) ;
- `sorties/seuils.csv` — la sensibilité des seuils numériques.

Option : `--sorties <dossier>` pour changer le dossier d'écriture (par défaut `sorties/`).

Pour tout relancer d'un coup :

```bash
for s in reference entree progression impact chronologie detections; do python3 src/$s.py --donnees donnees; done
```

`demarrage.py` est le script de départ fourni par le cours (chargement et volumes) ;
il est conservé tel quel et n'est pas utilisé par l'analyse.

## 4. Organisation du dépôt

```
operation-brume/
├── README.md
├── requirements.txt
├── demarrage.py              # script fourni par le cours (inchangé)
├── donnees/                  # les 7 journaux — NON versionné
├── src/
│   ├── chargement.py         # chargement commun + utilitaires (preuves, affichage)
│   ├── reference.py          # niveau 1 — référence « normale »
│   ├── entree.py             # niveau 2 — point d'entrée
│   ├── progression.py        # niveau 3 — progression dans le réseau
│   ├── impact.py             # niveau 4 — exfiltration, EDR, périmètre
│   ├── chronologie.py        # niveau 5 — frise + IOC (écrit sorties/)
│   └── detections.py         # niveau 5 — règles de détection, rétro-test, chasse
├── docs/
│   └── recommandations.md    # recommandations priorisées (s'appuie sur sorties/regles.csv)
└── sorties/
    ├── chronologie.csv
    ├── ioc.csv
    ├── regles.csv
    └── seuils.csv
```

## 5. Comment fonctionne l'analyse

### 5.1 Démarche

L'analyse suit les conseils méthode du sujet :

1. **Établir la normale d'abord** (`reference.py`) : volumes par jour, rythme
   horaire, clés de jointure. On ne repère l'anormal que par contraste.
2. **Partir d'un indice fort de chaque source, puis suivre le fil** : un
   courriel, un clic, une connexion étrangère, une rafale d'échecs, un balayage,
   un envoi volumineux, une alerte critique. Chaque indice est ensuite recoupé
   avec les autres journaux (même compte, même IP, même créneau).
3. **Tout ramener à une frise commune** (`chronologie.py`) : un seul fuseau,
   un seul format d'évènement, tri chronologique.
4. **Prouver, pas deviner** : chaque évènement porte une référence
   `fichier:Lligne`. Ce qui n'est pas prouvé est étiqueté comme hypothèse
   ou comme confiance « moyenne ».

### 5.2 Principes de conception

| Principe | Mise en œuvre |
|---|---|
| **Rejouable** | Aucun aléa, aucun accès réseau ; mêmes données ⇒ mêmes sorties. |
| **Rien en dur** | Pas de nom de compte, d'IP ni de date dans le code : acteurs et seuils sont **dérivés des données** (ex. seuil d'envoi = 100 × le 99ᵉ centile des octets envoyés). |
| **Preuve par ligne** | `chargement.py` ajoute une colonne `ligne` à chaque source ; `preuve()` produit `vpn_auth.csv:L1349`. |
| **Un seul fuseau** | Tous les horodatages (tous en `+02:00`) sont convertis en `Europe/Paris`. |
| **Pas de `dropna` global** | Les valeurs vides sont **voulues** (`motif` vide = connexion réussie, `piece_jointe` vide = mail sans PJ…). |
| **Jointures prudentes** | Les IP de serveurs sont uniques ; celles des postes ne le sont pas (4 IP partagées par 2 postes). On ne joint donc « IP → machine » que sur les **serveurs**. |
| **Médianes, pas moyennes** | Les moyennes contiennent déjà l'attaque ; les médianes y résistent. |

### 5.3 Clés de jointure entre sources

La colonne `ip_source` ne désigne pas la même chose partout :

| Source | `ip_source` / clé | Rattachement à l'inventaire |
|---|---|---|
| `vpn_auth.csv` | IP **publique** externe | `login` ↔ `proprietaire` |
| `proxy_web.csv` | **nom de poste** (pas une IP) | `hostname` ; `login` = propriétaire |
| `ad_events.jsonl` | **nom de poste** (ou IP externe pour l'attaquant) | `hostname` ; `utilisateur` ↔ `proprietaire` |
| `firewall.csv` | IP **interne** | `ip` (serveurs uniquement) |
| `mail_gateway.csv` | adresses mail | partie avant `@` ↔ `proprietaire` |
| `edr_alerts.json` | `machine` + `utilisateur` | `hostname` ; `utilisateur` ↔ `proprietaire` |

### 5.4 Enchaînement des scripts

```
 chargement.py  ←── utilisé par tous les scripts (lecture, preuves, affichage)

 reference.py            (autonome : niveau 1)

 entree.py ──► ip_attaquant, victime, poste ─┐
                                             ▼
 progression.py ◄─ ip_attaquant ──► ip_pivot, flux du pivot ─┐
                                                             ▼
 impact.py ◄── ip_attaquant + flux du pivot ──► exfiltration, périmètre

 chronologie.py : appelle entree, progression et impact, fusionne leurs
                  évènements, écrit sorties/chronologie.csv et sorties/ioc.csv

 detections.py  : appelle aussi entree, progression et impact (pour savoir ce qui est « l'attaque »),
                  puis rejoue 28 règles sur les journaux ; écrit sorties/regles.csv et sorties/seuils.csv
```

Chaque module expose une fonction `analyser(d)` qui **retourne** ses résultats
(DataFrames, dictionnaires) et une liste d'évènements ; la fonction `main()`
ne fait que les afficher. C'est ce qui permet à `chronologie.py` de tout
réutiliser sans dupliquer de logique.

## 6. Ce que fait chaque script

### `src/chargement.py` — socle commun

- `charger(dossier)` lit les 7 sources et renvoie un dictionnaire de DataFrames
  (`vpn`, `proxy`, `firewall`, `mail`, `ad`, `edr`, `inventaire`).
- Convertit `horodatage` en date/heure **Europe/Paris** (avec fuseau).
- Ajoute `ligne` : numéro de ligne **dans le fichier brut** (CSV : en-tête = ligne 1 ;
  JSON Lines : première donnée = ligne 1 ; EDR : identifiant `EDR-xxxxx`).
- Utilitaires : `preuve()` / `preuves()` (références de preuve), `evenement()`
  (une ligne de la frise), `est_interne()` (nom de poste ou IP `10.x`),
  `lire_args()`, `titre()`, `montrer()`.

### `src/reference.py` — niveau 1 : comprendre les données

**Question :** combien d'utilisateurs, de postes, de serveurs ? sur quelle période ?
à quoi ressemble une journée normale ?

- Compte postes, serveurs, propriétaires et comptes vus dans l'AD ; donne la période couverte.
- Par source : **médiane** du volume par jour ouvré et par week-end, et part des
  évènements tombant entre 8h et 18h en semaine. Constat : VPN, proxy, AD et mail
  suivent les horaires de bureau ; le pare-feu garde un fond nocturne (≈ 7 % des flux entre 22h et 6h) et un
  volume au moins égal le week-end ; l'EDR émet ≈ 10 alertes par jour, week-end compris, dont aucun faux positif la nuit.
- Liste les **clés absentes de l'inventaire** (comptes AD, IP AD, IP pare-feu, utilisateur EDR) :
  à comprendre, pas à supprimer.
- Signale les **IP partagées** par deux postes (piège de jointure).

### `src/entree.py` — niveau 2 : le point d'entrée

**Question :** quel compte a été compromis en premier, comment, depuis où ?

1. **`courriel_piege`** — parmi les mails **livrés**, cherche ceux cumulant au moins
   2 indices : domaine expéditeur *sosie* d'un domaine habituel (`difflib`, ressemblance ≥ 0,9),
   pièce jointe à **double extension** (`.pdf.htm`…), présence d'un **lien**, score
   de risque à moins de 15 points du seuil de blocage. Le seuil n'étant pas documenté,
   il est **encadré par les données** : plus haut score livré / plus bas score bloqué.
2. **`clic_et_identifiants`** — cherche dans le proxy les visites du destinataire vers
   l'hôte du lien après la réception ; un `POST` indique l'envoi d'un formulaire
   (identifiants probablement saisis). Cherche l'alerte EDR émise sur ce poste dans les 30 min.
3. **`acces_vpn_suspects`** — détermine le **pays habituel** du compte (mode avant l'incident),
   isole ses connexions depuis un autre pays, puis relit **toute l'activité de cette IP**
   (échecs puis succès, durée des sessions).

Il signale aussi deux incohérences : une même IP géolocalisée dans plusieurs pays,
et des sessions VPN qui se chevauchent.

### `src/progression.py` — niveau 3 : la progression

**Question :** balayage ? compte à privilèges ? compte de persistance ?

- **`rafales_echecs`** — regroupe les échecs d'authentification (évènement 4625)
  par couple (compte, source) en *épisodes* (écart < 10 min) ; un épisode de ≥ 5 échecs
  est une rafale. Regarde ensuite, dans l'heure, ce qui suit pour la même source :
  connexion réussie (4624, type 10 = bureau à distance), privilèges spéciaux (4672),
  création de compte (4720), ajout à un groupe (4728). Le motif distingue
  « mauvais mot de passe » (devinette) de « accès refusé » (identifiants valables, droits insuffisants).
- **`balayages`** — fenêtres d'une minute par source : une source touchant ≥ 10 couples
  (serveur:port) distincts est un balayage. Compare au maximum « normal » observé
  et au taux de blocage habituel du pare-feu ; indique si la source figure à l'inventaire.
- **`activite_pivot`** — liste tous les flux de la source suspecte avec le nom du serveur visé
  (jointure sur les serveurs uniquement).
- **`comptes_crees`** — examine chaque création de compte selon 5 critères
  (nuit, week-end, source externe, ajout à un groupe, connexions ultérieures).
  Est **suspect** un compte ajouté à un groupe d'administration **et** créé de nuit
  ou depuis l'extérieur. Les autres sont écartés avec leurs réserves.
- **`couverture_vpn`** — mesure quelle part de l'activité de l'attaquant (AD et pare-feu)
  tombe dans une session VPN journalisée (contrôle de cohérence entre sources).

### `src/impact.py` — niveau 4 : l'impact

**Question :** y a-t-il eu exfiltration ? combien ? quelles alertes ont été ignorées ?

- **`exfiltration`** — isole les requêtes dont le volume **envoyé** dépasse 100 × le p99 des
  octets envoyés, les regroupe par (compte, poste, hôte, URL, méthode), donne le total en
  octets, **Go** (décimal) et **Gio**, la durée, le débit, et la première apparition de l'hôte
  dans tout le journal.
- **`alertes_edr`** — extrait les alertes encore **ouvertes** et calcule le contexte de bruit :
  part de faux positifs, alertes par jour, alertes hors horaires ouvrés.
  Les causes de l'inaction sont présentées comme des **hypothèses**, non prouvées.
- **`perimetre`** — une ligne par machine avec un niveau de certitude :
  **accès réussi** (action réussie dans l'AD depuis l'IP de l'attaquant, flux RDP autorisé
  du pivot après le balayage, ou alerte EDR ouverte) ou **sondé** (refus ou balayage seulement).

### `src/chronologie.py` — niveau 5 : frise et indicateurs

**Question :** quelle est la chronologie complète ? quels sont les indicateurs de compromission ?

- **`construire`** exécute `entree`, `progression` et `impact`, fusionne leurs évènements
  et les trie dans le temps (tri stable).
- **`indicateurs`** produit le tableau des IOC : expéditeur, pièce jointe, URL et domaines
  d'hameçonnage / d'exfiltration, comptes (compromis ou créés), IP externe et interne,
  machines touchées, chacun avec un **niveau de confiance** et sa preuve.
- Écrit `sorties/chronologie.csv` et `sorties/ioc.csv`.

### `src/detections.py` — niveau 5 (suite) : les règles de détection

**Question :** quelles règles auraient repéré l'attaque plus tôt, avec quels seuils, sans noyer le SOC ?
Existe-t-il d'autres compromissions que celles déjà reconstituées ?

- **Catalogue de 15 règles (R01 à R15) en 28 variantes** : chaque règle existe en variante *stricte*
  (celle retenue), *large* (seuil assoupli, pour chasser) et parfois *naïve* (règle simpliste, pour
  montrer pourquoi elle est inutilisable). Chaque règle est une fonction `r_…(d, paramètre)` qui renvoie
  ses alertes (horodatage, acteurs, preuve, détail). Familles : courriel (R01), proxy (R02, R15),
  EDR (R03, R04), VPN (R05, R06), Active Directory (R07 à R11), pare-feu (R12 à R14).
- **`contexte`** déduit « ce qu'est l'attaque » (comptes, IP, domaines, repères horaires) en réutilisant
  `entree`, `progression` et `impact` ; **`rattachee`** décide si une alerte relève de l'attaque (IP ou domaine
  connu, ou compte compromis *pendant* l'attaque) ; toutes les autres sont des **faux positifs ou des pistes**.
- **`retro_test`** rejoue chaque règle sur les 3 semaines et calcule : alertes, rattachées, faux positifs,
  heure de la première alerte utile, **avance** sur l'exfiltration et sur le chiffrement, et volume (Mo) déjà
  exfiltré au moment de l'alerte.
- **`sensibilite`** fait varier le seuil des règles numériques (échecs, couples serveur:port, octets par heure,
  score du mail) et donne la **plage de seuils sans faux positif qui détecte encore l'attaque**.
- **`pistes`** regroupe les alertes *non rattachées* des variantes stricte/large : ce sont les autres
  compromissions possibles ; **`presence`** montre où un compte apparaît pour juger si la piste est corroborée.
- **`audit_clotures`** vérifie que le motif de clôture des alertes EDR « faux positif » est cohérent avec le
  service de l'utilisateur concerné.

## 7. Paramètres et seuils

Tous sont des constantes en tête des modules, justifiées par la distribution normale des données :

| Paramètre | Valeur | Script | Rôle |
|---|---|---|---|
| `MARGE_SEUIL` | 15 points | `entree.py` | un mail livré à moins de 15 points du plus bas score bloqué est « limite » |
| `MIN_MAILS_USUEL` | 50 mails | `entree.py` | un domaine expéditeur est « habituel » à partir de 50 mails |
| ressemblance de domaine | ≥ 0,9 | `entree.py` | détection d'un domaine sosie |
| fenêtre EDR après clic | 30 min | `entree.py` | alerte considérée comme liée au clic |
| `SEUIL_ECHECS` / `FENETRE_ECHECS` | 5 échecs / 10 min | `progression.py` | définition d'une rafale |
| `SEUIL_COUPLES` / `FENETRE_SCAN` | 10 couples / 1 min | `progression.py` | définition d'un balayage |
| nuit | 22h – 6h | `progression.py` | création de compte « de nuit » |
| `FACTEUR_ENVOI` | 100 × p99 | `impact.py` | envoi « hors norme » |
| rafale (variantes) | 5 (stricte) / 3 (large) échecs en 10 min | `detections.py` | R09 |
| sondage de serveurs | 3 (stricte) / 2 (large) serveurs en 15 min | `detections.py` | R08 |
| balayage (variantes) | 10 (stricte) / 5 (large) couples/min | `detections.py` | R12 |
| volume envoyé | 50 Mo/h (stricte) / 1 Mo/h (large) | `detections.py` | R15 |
| nouvel hôte web | absent des 3 premiers jours, ≤ 5 comptes | `detections.py` | R02 |

Valeurs de référence observées sur ces données : jamais plus de 3 couples serveur:port par
minute et par source en temps normal, 6,1 % de flux bloqués en moyenne, 2 000 octets au plus
par requête normale, aucune autre rafale que les deux détectées.

## 8. Lire les sorties et vérifier une preuve

**`sorties/chronologie.csv`**

| Colonne | Contenu |
|---|---|
| `horodatage` | date et heure de Paris, avec décalage (`2026-09-11 10:48:00+0200`) |
| `phase` | `1 Accès initial`, `2 Compromission du compte`, `3 Progression`, `4 Privilèges et persistance`, `5 Exfiltration`, `6 Sabotage` |
| `preuve` | `fichier:Lligne` (plage `L5651-5658` ou liste), ou `fichier#identifiant` pour l'EDR |
| `evenement` | description en français |

**`sorties/ioc.csv`** : `type` (courriel, fichier, url, domaine, compte, ip, machine),
`valeur`, `role`, `confiance` (élevée / moyenne / faible), `preuve`.

**`sorties/regles.csv`** : une ligne par règle et variante — `code`, `regle`, `variante`, `alertes`, `rattachees`,
`faux_positifs`, `premiere_alerte_utile`, `avance_sur_exfiltration`, `avance_sur_chiffrement`, `Mo_deja_sortis`.
**`sorties/seuils.csv`** : pour chaque règle numérique et chaque seuil testé — `alertes`, `faux_positifs`,
`detectee`, `premiere_alerte_utile`, `Mo_deja_sortis`.

**Vérifier une preuve à la main** (le numéro de ligne est celui du fichier brut) :

```bash
sed -n '1153p' donnees/mail_gateway.csv        # CSV : ligne 1 = en-tête
sed -n '5659p' donnees/ad_events.jsonl         # JSON Lines : 1 objet par ligne
grep -A8 '"EDR-10203"' donnees/edr_alerts.json # EDR : par identifiant
```

## 9. Limites, incohérences et hypothèses

À assumer plutôt qu'à masquer :

- **Géolocalisation incohérente** : la même IP apparaît avec 4 pays différents ; deux sessions VPN
  du même compte se chevauchent.
- **Journal VPN lacunaire ou accès non journalisé** : une partie de l'activité de l'attaquant
  (connexions du compte de persistance, flux RDP du pivot) tombe hors de toute session VPN
  journalisée, et une connexion AD précède de 2 minutes le succès VPN correspondant.
- **Lien IP externe ↔ IP interne non prouvé** : le rapprochement de l'IP externe et de l'IP interne
  absente de l'inventaire repose sur la concordance horaire (confiance « moyenne »).
- **Second facteur** : deux échecs « second facteur manquant » puis un succès, sans trace de la
  façon dont le second facteur a été satisfait. Le mot de passe du compte privilégié n'est pas
  non plus expliqué par les journaux.
- **Volume exfiltré = minimum** : seul le proxy voit ce flux (le pare-feu ne journalise que du
  trafic interne) ; le lien avec les fichiers réellement lus ne peut pas être établi.
- **Étendue du chiffrement** : l'EDR ne cite qu'un serveur ; les autres serveurs touchés par RDP
  ne sont pas démontrés comme chiffrés.
- **Bruit écarté avec réserves** : trois comptes de recrues créés par un opérateur et une IP
  absents de l'inventaire (création en double, week-end) ; rien ne les relie à l'attaque.
- **Rétro-test sur l'attaque qui a inspiré les règles** : les règles et leurs seuils sont calibrés sur ces
  3 semaines de données et « l'attaque » est elle-même déduite des mêmes journaux : les résultats sont
  **optimistes** (risque de surapprentissage). Les marges de seuil donnent une idée de la robustesse,
  pas une garantie sur d'autres attaques ni sur un autre environnement.
- **Données de bruit homogènes** : le comportement « normal » (par ex. chaque poste joint tous les serveurs
  en RDP, SMB, LDAP et SQL ; l'IP d'un compte change presque chaque jour) est très régulier ; dans un
  vrai SI, certaines règles (pays inhabituel, nouvelle IP) produiraient davantage de faux positifs.
- **Un seul scénario** : `entree.py` retient le **premier** courriel suspect ; sur une variante
  comportant plusieurs victimes, il faudrait itérer sur `mails_suspects`.

## 10. Usage de l'IA

Conformément à l'énoncé, l'usage d'une IA générative est déclaré : ces scripts et ce README
ont été réalisés avec l'assistance de Claude, Gemini eet Mistral. Le code est exécuté, relu et
assumé par l'auteur.

