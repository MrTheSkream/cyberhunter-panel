# 7 - Statistiques web par site avec GoAccess (validée le 2026-11-16)

Choix validés :
- **Outil** : GoAccess.
- **Consultation** : dans le panel seulement, aucune URL publique.
- **Mise à jour** : toutes les heures, avec un bouton « Refresh ».
- **Historique** : 12 mois.
- **Fichiers statiques** : journalisés comme le reste.

## 1. Constat (code actuel)
- **Logs nginx par site** :
  - fichiers `/var/log/nginx/<domaine>.access.log` et `.error.log`, au format `combined` (aucun
    `log_format` défini) ;
  - rotation quotidienne par la configuration Debian (`/etc/logrotate.d/nginx`, 14 jours, `delaycompress`).
- **Mode Apache** (fonctionnalité 4) : Apache écrit ses accès dans `/dev/null`, donc **nginx reste le
  seul journal d'accès**.
- **Fichiers statiques** (`js|css|png|jpg|…`, plus quelques blocs comme xmlrpc) : `access_log off;` dans
  `http.conf` et `https.conf`. Conséquence : ils sont absents des logs, et donc aussi du **comptage de
  bande passante** et du quota de bande passante existants.
- **Contrainte forte** : la ligne `access_log /var/log/nginx/{domain}.access.log;` sert d'ancre à
  plusieurs recherches de texte (`site_access.rs:223`, `nginx.rs:581`, `routes/nginx.rs:1636`). fail2ban
  et les parseurs existants supposent le format `combined`. **On ne touche ni au format ni à cette
  ligne.**
- **Statistiques existantes** : le bloc « Traffic Stats » de la fiche du site ne lit que les 10 000
  dernières lignes du log (`/nginx/site-stats`). Il n'a ni historique ni graphique.
- **Import Hestia** : `STATS=''` sur tes 28 domaines, il n'y a rien à reprendre.
- **GoAccess** n'est pas installé. Ubuntu 24.04 fournit la version 1.8.1, liée à libmaxminddb (pays
  possibles).

## 2. Installation (Settings → Services → « Web statistics (GoAccess) »)
- **Paquet** : `goaccess` (Debian/Ubuntu). Sur RHEL : « Not supported on this server ».
- **Après l'installation**, tous les sites ont leurs statistiques, sans case à cocher par site. Le premier
  calcul démarre tout de suite.
- **Désinstallation** :
  - arrêt des mises à jour et retrait du paquet ;
  - `/var/lib/dockpanel/stats/` (rapports et historique) est conservé : une réinstallation reprend
    l'historique ;
  - un bouton séparé « Delete statistics data » efface ces données, avec confirmation.
- **Pays** :
  - le panel télécharge la base gratuite **DB-IP Country Lite** (format mmdb, licence CC BY 4.0) dans
    `/var/lib/dockpanel/geoip/`, puis la met à jour chaque mois ;
  - si le téléchargement échoue, les rapports sont produits sans les pays ;
  - le rapport affiche la mention obligatoire « IP Geolocation by DB-IP ».

## 3. Journaliser les fichiers statiques
- Les templates `http.conf` et `https.conf` perdent leurs `access_log off;`. Les blocs statiques écrivent
  alors dans le log du site, comme le reste.
- **Vhosts existants** : au démarrage, l'agent les met à jour, sur le même modèle que la reconciliation
  des pools PHP :
  - il retire les lignes `access_log off;` des vhosts gérés par le panel ;
  - il lance `nginx -t`, avec retour arrière en cas d'échec ;
  - il recharge nginx une seule fois.
- **Conséquences assumées** :
  - logs plus gros (environ 5 à 20 fois plus de lignes sur un site WordPress), avec une rotation
    inchangée ;
  - **la bande passante comptée augmente**, puisque les images sont désormais comptées ; une alerte de
    quota de bande passante peut donc apparaître sur un site proche de sa limite ;
  - fail2ban lit plus de lignes, ce qui ne coûte presque rien.

## 4. Calcul des statistiques
### Stockage par site
Les fichiers vivent dans `/var/lib/dockpanel/stats/<domaine>/` (root, 0700) :
- `db/` : la base persistante de GoAccess (`--persist` / `--restore`) ;
- `report.html` : le rapport généré ;
- `state.json` : la date du dernier calcul et une éventuelle erreur.

### Commande lancée par l'agent pour un site
```
goaccess /var/log/nginx/<d>.access.log.1 /var/log/nginx/<d>.access.log \
  --log-format=COMBINED --persist --restore --db-path=<dir>/db \
  --keep-last=365 [--geoip-database=<mmdb>] --no-global-config \
  --html-report-title=<domaine> -o <dir>/report.html
```
- **Lecture incrémentale** : on donne aussi `.1` en entrée pour ne rien perdre au moment d'une rotation.
  GoAccess garde en base la position de lecture de chaque fichier ; s'il ne la garde pas, il se repère
  sur l'horodatage de la dernière ligne lue. Les lignes déjà comptées sont donc ignorées. **C'est le
  point n°1 à vérifier dans la VM** : une ligne ne doit jamais être comptée deux fois.
- **Historique** : `--keep-last=365` garde 12 mois glissants.
- **Ressources** : `nice 19` et `ionice` en classe idle, un site à la fois, un seul calcul par serveur.
- **Premier calcul** : il ne voit que les logs encore présents (`.1` à `.14.gz`). Les `.gz` sont lus une
  seule fois, à l'initialisation, avec `zcat` en entrée standard.
- **Robots** : ils sont comptés dans un panneau séparé (option `--ignore-crawlers` non utilisée).
- **Requêtes du panel** : les vérifications de disponibilité du panel (uptime) portent le User-Agent
  `DockPanel-Uptime` et sont classées avec les robots. GoAccess ne sait pas exclure un User-Agent précis,
  il sait seulement le classer (fichier `--browsers-file`).

### Rythme
- Le backend lance un passage par serveur **toutes les heures**, en commençant par les sites jamais
  calculés ou les plus anciens, comme pour les quotas.
- Le bouton « Refresh » de la fiche du site recalcule ce site tout de suite (un calcul à la fois par site).
- Un échec sur un site laisse le rapport précédent en place et note l'erreur ; il ne bloque pas les autres
  sites.

### Cycle de vie
- La suppression du site supprime aussi son dossier de statistiques.
- Le renommage du site renomme le dossier. Les anciens logs gardent l'ancien nom et ne sont pas relus.

## 5. Consultation (fiche du site → section « Web statistics »)
- **Récupération** : le backend sert le rapport par
  `GET /api/sites/{id}/stats/report`. Les droits sont ceux de la fiche du site : admin, revendeur du
  propriétaire, propriétaire.
- **Isolation** : le rapport s'affiche dans une `iframe` **sandbox sans `allow-same-origin`**, remplie
  par `srcdoc` après un `fetch` authentifié.
  - Il contient des chaînes venues des visiteurs (URL, référents, User-Agent). GoAccess les échappe, et
    le bac à sable empêche tout script du rapport de toucher au panel, même en cas de faille.
  - Pourquoi `srcdoc` et pas `src` : le nginx du panel envoie `X-Frame-Options: DENY` et
    `frame-ancestors 'none'` sur toutes ses réponses, donc une URL du panel ne peut pas être affichée
    dans un cadre.
  - La réponse du backend porte `Content-Security-Policy: sandbox allow-scripts; ...` et
    `Content-Disposition: attachment`. Ouverte directement dans un onglet, elle reste isolée.
- **En-tête de la section** : « Updated 23 min ago », bouton « Refresh », bouton « Full screen » (le
  même cadre isolé, en plein écran), bouton « Download » (fichier HTML) et l'erreur éventuelle.
  - **Pas de bouton « Open in new tab »** : un onglet ouvert depuis le panel (blob ou `window.open`)
    prend l'origine du panel et perdrait l'isolation.
- **Mention DB-IP** : sous le cadre, « IP Geolocation by DB-IP » avec le lien vers db-ip.com (le rapport
  de GoAccess ne l'affiche pas lui-même).
- **Sans rapport** : avant le premier calcul, « Statistics are being prepared », et si GoAccess n'est
  pas installé, « Install Web statistics in Settings → Services ».
- **Bloc existant** : « Traffic Stats » (les dernières lignes, en direct) est conservé et renommé
  « Recent traffic ».

## 6. À vérifier en premier dans la VM
1. **Double comptage** : aucune ligne n'est comptée deux fois, même avec `.1` en entrée et des passages
   horaires, y compris juste avant et juste après une rotation (`logrotate -f`).
2. **Pays** : GoAccess 1.8.1 d'Ubuntu lit bien la base DB-IP mmdb.
3. **Vieux logs** : lecture des `.gz` au premier calcul.
4. **Sandbox** : le rapport fonctionne dans une `iframe` sans `allow-same-origin` (onglets, graphiques,
   thème sombre).
5. **Ressources** : durée et mémoire d'un passage complet sur les 31 sites, et taille des bases
   persistantes.
6. **Vhosts** : la mise à jour au démarrage des vhosts existants passe `nginx -t`, et les fichiers
   statiques apparaissent ensuite dans les logs, dans le comptage de bande passante et dans les
   statistiques.

## 7. Tests en VM (instantané avant)
- Installer GoAccess, attendre le premier calcul, puis ouvrir les statistiques de jeuxx.org :
  visiteurs, pages, pays, robots.
- Générer du trafic connu (N requêtes vers une URL marquée) :
  - après un « Refresh », la page compte exactement N ;
  - après un passage horaire, elle compte toujours N ;
  - après un `logrotate -f` suivi d'un nouveau passage, elle compte encore N.
- Requête d'une image : elle apparaît dans le log et dans les statistiques.
- Droits : le propriétaire du site voit ses statistiques. Un autre utilisateur reçoit 404 sur le
  rapport.
- Désinstaller : les données sont conservées. Réinstaller : l'historique revient. « Delete statistics
  data » vide le dossier.
- Supprimer un site de test : son dossier de statistiques disparaît.
