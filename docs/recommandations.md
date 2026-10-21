# Recommandations — Opération Brume

Ce document s'appuie sur la chronologie (`sorties/chronologie.csv`), les indicateurs
(`sorties/ioc.csv`) et le rétro-test des règles de détection (`sorties/regles.csv`,
`sorties/seuils.csv`, produits par `src/detections.py`). Chaque chiffre renvoie à ces fichiers.
Les mesures qui relèvent de bonnes pratiques générales, et non d'une preuve tirée des journaux,
sont signalées comme telles.

## 1. Constat

L'attaque a duré **9 jours** (vendredi 11/09 10:48 → dimanche 20/09 05:25) et a franchi
**six étapes**, dont chacune a laissé une trace exploitable :

1. courriel piégé livré, puis clic et saisie d'identifiants (11/09) ;
2. connexion VPN depuis une IP étrangère avec le compte volé (11/09, 23:17) ;
3. sondage, puis balayage interne des 8 serveurs (12/09, ~01:00) ;
4. prise du compte à privilèges `n.vincent` et création d'un compte administrateur (14/09, 02:05–02:30) ;
5. exfiltration de **0,894 Go** vers un hôte jamais vu (19/09, 03:37–04:04) ;
6. suppression des sauvegardes puis chiffrement (20/09, 03:59 et 05:25).

**Rejouées sur les journaux, les règles ci-dessous auraient donné l'alerte dès la première étape,
soit 7 j 16 h avant l'exfiltration et 8 j 18 h avant le chiffrement, sans aucun faux positif**
pour les variantes « strictes ». Le problème n'était donc pas l'absence de traces, mais l'absence
de réaction : 5 alertes EDR sont restées « ouvertes » (dont les 4 critiques, toutes déclenchées
de nuit ou le week-end).

## 2. Règles de détection à déployer

« Normal » = valeur maximale observée sur 3 semaines hors attaque. Une règle est d'autant plus
robuste que son seuil est éloigné du normal. L'avance se mesure par rapport au chiffrement (20/09 05:25).

| Règle | Seuil recommandé | Normal → attaque | Première alerte | Avance | Faux positifs |
|---|---|---|---|---|---|
| **R01** Courriel livré cumulant ≥ 2 indices (domaine sosie, double extension, lien, score proche du seuil) | quarantaine dès **score ≥ 40–50** ; le seuil de blocage actuel est entre 59 et 70 | 30 → 58 | 11/09 10:48 | 8 j 18 h | 0 |
| **R02** Hôte web jamais vu + envoi de formulaire (POST) | 1ʳᵉ visite d'un hôte absent des 3 premiers jours, ≤ 5 comptes | – | 11/09 11:14 | 8 j 18 h | 0 |
| **R03** Alerte EDR non close, **toute gravité** | traitement sous 1 h ouvrée | – | 11/09 11:20 | 8 j 18 h | 0 |
| **R04** Alerte EDR entre 22h et 6h | toute alerte | 0 faux positif la nuit sur 203 | 14/09 02:57 | 6 j 2 h | 0 |
| **R05** VPN : succès après échec « second facteur manquant » | ≤ 5 min, même compte et même IP | 0 → 2 | 11/09 23:17 | 8 j 6 h | 0 |
| **R06** VPN : même compte dans 2 pays en < 10 min | déplacement impossible | 0 → 2 | 11/09 23:15 | 8 j 6 h | 0 |
| **R07** Authentification AD depuis une source hors parc | IP non interne | 0 → 21 | 12/09 00:58 | 8 j 4 h | 0 |
| **R08** Refus d'accès sur ≥ 3 serveurs différents | 15 min | 1 → 6 | 12/09 01:02 | 8 j 4 h | 0 |
| **R09** Rafale d'échecs d'authentification | **3 échecs / 10 min** (plage sûre : 2 à 8) | 1 → 6 et 8 | 12/09 01:02 | 8 j 4 h | 0 |
| **R10** Session RDP interactive (type 10) sur AD | toute occurrence | 0 → 1 | 14/09 02:05 | 6 j 3 h | 0 |
| **R11** Privilèges spéciaux + création de compte + ajout à un groupe admin, même source, en 1 h | toute séquence | 0 → 1 | 14/09 02:30 | 6 j 3 h | 0 |
| **R12** Balayage pare-feu | **5 couples serveur:port / min** (plage sûre : 4 à 40) | 3 → 40 | 12/09 01:05:04 | 8 j 4 h | 0 |
| **R13** Flux sur un port quasi inutilisé (SSH) | port utilisé par < 1 % des sources | – | 12/09 01:05:01 | 8 j 4 h | 0 |
| **R14** IP source absente de l'inventaire | première apparition | – | 12/09 01:05:01 | 8 j 4 h | 0 |
| **R15** Volume envoyé vers un hôte | **10 Mo/h : alerte ; 100 Mo/h : blocage automatique** (plage sûre : 10 Ko à 500 Mo) | 6,5 Ko → 894 Mo | 19/09 03:37 (alerte) / 03:40 (blocage) | – | 0 |

**Pour R15, la rapidité compte plus que l'avance** : avec une alerte à 10 Mo/h, 13 Mo seulement
étaient sortis ; avec un blocage à 100 Mo/h, 106 Mo sur 894 (soit environ 88 % du volume évité).

**Règles à ne pas déployer** (rétro-test) : « mail livré avec score ≥ 30 » (58 faux positifs pour 1 vrai),
« IP VPN jamais vue pour le compte » (1 827 faux positifs pour 16 vrais : les utilisateurs changent d'IP
presque chaque jour), « ≥ 5 échecs cumulés sur 3 semaines » (4 faux positifs), « toute création de compte »
(4 faux positifs).

**Corrélation recommandée plutôt que des alertes isolées** : une règle seule peut être bruyante en
production ; l'enchaînement R01 → R02 → R05/R06 → R07 → R09 → R10 → R11 sur le même compte ou la même IP
doit faire monter la gravité automatiquement (un seul de ces signaux = ticket ; deux = incident).

## 3. Mesures correctives, par priorité

### P0 — Confinement et éradication (immédiat, 0 à 48 h)

*Bonnes pratiques de réponse à incident ; les comptes et machines viennent de `ioc.csv`.*

- **Désactiver `svc_monitoring`**, réinitialiser les mots de passe de `l.perrin` et `n.vincent`, et
  **considérer tout le domaine comme compromis** : le compte créé a été ajouté à « Admins du domaine ».
  Réinitialiser les comptes à privilèges, les comptes de service et le compte `krbtgt` (deux fois).
- **Bloquer les indicateurs** : IP `203.0.113.87`, domaines `nordis-compta-auth.example`,
  `cloud-depot-securise.example` et `fourniseur-x.example`, sur la messagerie, le proxy, le DNS et le pare-feu.
- **Isoler et analyser** : PC-SIE-1000, SRV-AD01, SRV-FILE01, SRV-FILE02, SRV-BACKUP01 (accès réussi) ;
  vérifier SRV-ERP01, SRV-PROXY01 et SRV-VPN01 (sondés).
- **Restaurer** depuis des sauvegardes saines : celles qui étaient en ligne ont été visées (alerte de
  suppression de sauvegardes le 20/09 à 03:59).
- **Évaluer l'obligation de notification** (0,894 Go sortis, contenu inconnu) avec le DPO et le juridique.

### P1 — 30 jours : fermer les trous qui ont permis l'attaque

| Mesure | Pourquoi (preuve) |
|---|---|
| **Activer R01–R15** (§2) dans le SIEM, avec corrélation par compte et IP | 15 règles sans faux positif ; alerte possible dès le 11/09 |
| **Escalade automatique des alertes EDR** : page d'astreinte pour toute alerte critique, SLA de traitement, interdiction de laisser une alerte « ouverte » sans propriétaire | 5 alertes ouvertes, dont 4 critiques de nuit ou de week-end |
| **Revue des clôtures EDR** : motif obligatoire et cohérent | 47 clôtures « export comptable » sur 53 concernent des non-comptables ; 50 « PsExec utilisé par l'IT » sur 53 et 40 « maintenance » sur 44 concernent des non-IT |
| **Second facteur résistant à l'hameçonnage** (FIDO2) sur VPN et comptes à privilèges ; alerte sur échec puis succès du 2ᵉ facteur | deux échecs « second facteur manquant », puis succès en 3 min sans trace de la méthode |
| **Filtre de messagerie** : abaisser le seuil de blocage, rejeter les pièces jointes `.htm/.html` et les doubles extensions, détecter les domaines sosies, imposer SPF/DKIM/DMARC | mail livré avec un score de 58 alors que tous les autres livrés étaient ≤ 30 |
| **Proxy** : bloquer ou isoler les domaines jamais vus et les POST vers des hôtes nouveaux ; plafonner l'envoi par hôte | exfiltration de 894 Mo vers un hôte inconnu, en 28 min |

### P2 — 90 jours : réduire la surface d'attaque

| Mesure | Pourquoi (preuve) |
|---|---|
| **Segmenter le réseau** : seuls des postes d'administration (rebond) joignent les serveurs en RDP ; interdire le RDP depuis les postes et depuis le pool VPN | les 297 postes actifs utilisent tous RDP, SMB, LDAP et SQL, et le RDP est ouvert vers les 8 serveurs ; le pivot a utilisé le RDP vers FILE01, FILE02 et BACKUP01 |
| **Comptes d'administration dédiés** (poste d'administration, PAM, durée limitée) ; interdire la connexion RDP interactive des comptes IT depuis Internet | `n.vincent` s'est connecté en RDP sur SRV-AD01 depuis une IP externe, 1 seule session de type 10 en 3 semaines |
| **Sauvegardes immuables et hors ligne** ; test de restauration régulier | suppression des sauvegardes avant le chiffrement |
| **Journalisation VPN complète et corrélée** (session, IP attribuée, pays fiable) | des évènements de l'attaquant tombent hors de toute session VPN journalisée |
| **Inventaire complet et à jour** : IP `10.10.200.41`, `10.10.5.12`, 4 IP partagées par 2 postes | l'inventaire a empêché d'attribuer des flux à une machine ou à un utilisateur |

### P3 — 6 mois : durcir et entraîner

- Sensibilisation à l'hameçonnage ciblée (comptabilité) et exercices de simulation.
- Exercices de gestion de crise avec rejeu de cette chronologie.
- Objectifs mesurables : **délai de détection < 1 h** pour R01–R03, **blocage automatique** de l'exfiltration,
  **0 alerte critique sans propriétaire**.

## 4. Points ouverts à lever hors journaux

- **Pistes non corroborées** : 4 créations de comptes `n.recrue*` par `j.admin_rh` depuis `10.10.5.12`
  (2 le week-end, un compte créé deux fois) ; cet opérateur et cette IP sont absents de l'inventaire et
  `j.admin_rh` n'a **aucune authentification enregistrée**. Rien ne les relie à l'attaque ; à vérifier auprès des RH.
- **Identité de `10.10.200.41`** : machine non inventoriée (pool VPN, poste inconnu ?). Son lien avec l'IP
  externe n'est établi que par la concordance horaire.
- **Accès hors session VPN** : à expliquer par l'exploitation du VPN (sessions non journalisées ?).
- **Contournement du second facteur** et **origine du mot de passe de `n.vincent`** : non visibles dans les journaux.
- **Étendue réelle du chiffrement et des données lues** : seul FILE01 est cité par l'EDR ; les journaux
  ne disent pas quels fichiers ont été copiés.

## 5. Limites de ces recommandations

Les seuils proviennent d'un rétro-test sur **cet incident et ces 3 semaines** : ils sont optimistes
(les règles sont calibrées sur ce qu'elles doivent trouver). Avant déploiement, les rejouer sur un historique
plus long et prévoir des listes d'exceptions (déplacements professionnels, administrateurs légitimes en RDP).
