# 13 - Scanner de CVE pour tout le serveur (à valider)

Objectif : remonter toute CVE publiée qui touche un composant installé sur un serveur géré, quel que soit son
langage (PHP, Java, Node, Python, Go, Ruby, Rust, paquets du système, images Docker, extensions WordPress),
et prévenir dès qu'une nouvelle CVE sort pour un composant déjà en place.

## 1. Constat (code actuel)

- **Images Docker** : grype est intégré (`agent/src/services/image_scanner.rs`), installé à la demande dans
  `/var/lib/dockpanel/scanners/`. Il ne scanne que l'image d'une application Docker, désactivé par défaut.
- **SBOM** : syft est intégré (`agent/src/services/sbom_scanner.rs`), à la demande, sans balayage planifié.
- **WordPress** : `agent/src/services/wp_vulnerability.rs::check_known_vulns` compare les extensions à une
  liste écrite en dur de 14 entrées. Le code dit lui-même qu'il faudrait une vraie base. Le cœur et les
  thèmes ne sont pas comparés à des CVE.
- **Non couverts** : dépendances des sites (`composer.lock`, `package-lock.json`, `.jar`, `requirements.txt`,
  etc.), images des déploiements Git, paquets du système, binaires Go et Rust.
- **Pas de détection des nouvelles CVE** : un scan photographie l'instant. Rien ne compare deux scans pour
  annoncer ce qui vient d'apparaître.

## 2. Principe

Deux étapes séparées, pour que l'arrivée d'une CVE ne demande pas de tout rescanner :

1. **Inventaire (syft)** : chaque cible produit un SBOM, recalculé seulement quand la cible change
   (déploiement, mise à jour d'une extension, changement d'empreinte des fichiers de dépendances) et une
   fois par semaine par sécurité.
2. **Correspondance (grype)** : chaque jour, après la mise à jour de la base de grype, tous les SBOM sont
   recomparés (`grype sbom:<fichier>`, quelques secondes chacun). Une CVE publiée la veille sur un composant
   déjà installé est donc trouvée sans rescanner les disques.

La base de grype agrège NVD, GitHub Security Advisories et les avis des distributions. Elle couvre
Composer, npm, yarn, pnpm, Maven (`.jar`, `.war`, `.ear`, y compris imbriqués, donc Log4Shell et
Spring4Shell), PyPI, RubyGems, Go, Cargo, NuGet, dpkg et apk.

## 3. Cibles

| Cible | Ce que syft lit | Déclencheur de l'inventaire |
|---|---|---|
| Chaque site | Son dossier web : fichiers de dépendances, `vendor/`, `node_modules/`, archives Java | Création, modification des fichiers de dépendances, chaque semaine |
| Chaque site WordPress | Version du cœur, extensions et thèmes avec leur version (wp-cli, sans exécuter leur code) | Chaque scan, car les extensions changent sans fichier de dépendances |
| Chaque application Docker et pile compose | Son image | Déploiement, mise à jour d'image |
| Chaque déploiement Git | Son image construite | Chaque déploiement réussi |
| Le système de chaque serveur | Base dpkg (paquets apt) | Chaque jour |
| Le panel lui-même | Ses binaires et son image PostgreSQL | Chaque mise à jour du panel |

## 4. WordPress

grype ne connaît pas les extensions WordPress. Il faut une base dédiée :

- **Proposition** : le flux public de Wordfence Intelligence (cœur, extensions, thèmes, versions affectées
  et corrigées, score CVSS). Il est synchronisé une fois par jour sur le panel, jamais interrogé par site.
- **À vérifier avant de valider** : les conditions actuelles du flux (clé gratuite requise ou non, licence
  d'usage dans un panel). Autre choix possible : l'API WPScan, gratuite seulement en dessous d'un faible
  quota quotidien.
- La liste écrite en dur de `check_known_vulns` est supprimée.

## 5. Priorisation

Chaque CVE porte :

- sa gravité (CVSS) et la version qui la corrige, si elle existe ;
- **exploitée activement** : présence dans le catalogue KEV de la CISA (synchronisé chaque jour) ;
- **probabilité d'exploitation** : score EPSS. À vérifier : la version de grype embarquée doit fournir KEV
  et EPSS dans sa sortie JSON, sinon le panel les synchronise lui-même ;
- **atteignable** : composant exposé sur un domaine public ou non, port lié à 127.0.0.1 ou non.

Ordre d'affichage : exploitée activement d'abord, puis critique, puis haute.

## 6. Alertes

- **Nouvelle CVE** : comparaison avec le résultat précédent de la même cible. Seules les CVE nouvelles
  déclenchent une alerte, une seule par cible et par jour, qui liste toutes les nouveautés.
- **Seuil par défaut** : toute CVE du catalogue KEV, et toute CVE critique ou haute avec un correctif
  disponible. Le reste apparaît dans l'interface sans alerte.
- **Résolution** : l'alerte se clôt seule quand la CVE disparaît du résultat.
- **Exceptions** : une CVE peut être acceptée pour une cible, avec un motif et une date d'expiration. Elle ne
  déclenche plus d'alerte jusqu'à cette date.
- Les alertes passent par le système de notifications existant. Elles n'ouvrent **pas** d'incident
  `major` ou `critical`, sinon tous les déploiements Git seraient bloqués.

## 7. Interface et API (libellés en anglais)

- Une page **Vulnerabilities** : toutes les cibles, filtres par gravité, KEV, cible et serveur, avec le
  composant, la version installée et la version corrigée.
- Un badge sur chaque site, application et déploiement Git.
- Routes prévues : `GET /api/vulnerabilities` (filtres), `GET /api/vulnerabilities/targets/{id}`,
  `POST /api/vulnerabilities/targets/{id}/scan`, `POST /api/vulnerabilities/{id}/accept`,
  `GET /api/vulnerabilities/settings` et `PUT`.
- Le seuil de refus au déploiement existant (images) est conservé et étendu aux déploiements Git.

## 8. Limites assumées

- Le code écrit à la main n'a pas de CVE : une faille propre à l'application n'est pas détectée. Cela
  relève d'un outil d'analyse de code ou d'un test d'intrusion, hors de cette fonctionnalité.
- Un composant copié sans métadonnées (un `.js` minifié sans `package.json`, un `.jar` renommé sans
  manifeste) peut échapper à syft.
- Une CVE sans entrée dans les bases (annonce trop récente, logiciel confidentiel) ne remonte pas avant
  son ajout, en général sous quelques heures pour GitHub Security Advisories.
- Le scan d'un gros `node_modules` coûte du disque et du processeur : un seul inventaire à la fois par
  serveur, en priorité basse.

## 9. Décisions à prendre

1. **Base WordPress** : Wordfence Intelligence (proposé) ou WPScan.
2. **Activation** : activé par défaut à l'installation, ou opt-in comme aujourd'hui.
3. **Seuil d'alerte** : celui de la section 6, ou toute CVE critique même sans correctif.
4. **Refus au déploiement** : le garder optionnel ou l'activer par défaut pour les CVE du catalogue KEV.
5. **Ordre** : le chantier des sauvegardes est en cours. Celui-ci passe après, ou le remplace en priorité.

## 10. Recette prévue (VM)

- Un site avec un `composer.lock` contenant une version vulnérable connue, un site Node avec un
  `package-lock.json` vulnérable, une application Java avec un `log4j-core` 2.14.1 : chaque CVE attendue
  remonte, Log4Shell marquée comme exploitée activement.
- Un WordPress avec une extension dans une version vulnérable connue.
- Un paquet apt volontairement en retard sur la VM.
- Simulation d'une nouvelle CVE : base de grype figée à une date, puis mise à jour : seule la nouveauté
  déclenche une alerte.
- Mise à jour du composant vulnérable : l'alerte se clôt seule.
