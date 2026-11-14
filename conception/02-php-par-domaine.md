# Fonctionnalité 2 - Réglages PHP par domaine (proposition à valider)

## 1. Point de départ

**CyberHunter - Panel aujourd'hui** (Ubuntu) :
- un pool PHP-FPM par site (`/etc/php/X.Y/fpm/pool.d/<site>.conf`), utilisateur `www-data`
  (ou l'utilisateur SFTP du site), socket dédiée, versions 8.1 → 8.5, changement de version possible ;
- réglables : mémoire (`php_memory_mb`) et nombre de workers (`php_max_workers`), c'est tout ;
- **en dur** : `upload_max_filesize = post_max_size = 64M` (alors que nginx peut accepter plus :
  les envois > 64 Mo échouent côté PHP), `max_execution_time = 300`, `pm = dynamic` ;
- **aucune isolation** : pas d'`open_basedir`, pas de `disable_functions`, sessions et fichiers
  temporaires partagés dans `/tmp`, pas de journal d'erreurs par site (le visualiseur « PHP errors »
  cherche un fichier que rien ne crée) ;
- **fragile** : fichier de pool écrit sans copie de secours, aucun `php-fpm -t` avant reload ;
  l'ancien pool reste actif après un changement de version.

**HestiaCP** :
- même principe de pool par domaine, mais tourne sous **l'utilisateur Hestia du domaine** ;
- modèle de pool : `pm = ondemand`, `max_children 8`, `max_requests 4000`, `idle 10s` ;
  `open_basedir` = dossiers du domaine + `~/tmp` + `/tmp` + binaires ; sessions et uploads dans
  `~/tmp` ; `sendmail_path … -f admin@domaine` ;
- version = « Backend template » `PHP-X_Y` ; changement = pool déplacé, vhost reconstruit ;
- **pas de réglage php.ini par domaine dans l'interface** : uniquement via `.user.ini` dans le site
  ou un modèle de pool personnalisé ; seul le `php.ini` global (par version) est éditable ;
- `disable_functions` global (FPM) : `exec, system, passthru, shell_exec, proc_open, popen` + `pcntl_*`.

## 2. Ce qu'on fait

Une carte **« PHP settings »** dans la fiche du site, qui écrit le pool du site. On va plus loin
que HestiaCP (réglages dans l'interface) tout en gardant ses garde-fous.

### 2.1 Réglages exposés (liste fermée, valeurs validées)

| Réglage | Défaut proposé | Bornes | Type de directive |
|---|---|---|---|
| `memory_limit` | 256M (colonne existante) | 32M – 4096M | `php_value` |
| `upload_max_filesize` | = limite d'upload nginx du site (`max_upload_mb`) | 1M – 2048M | `php_value` |
| `post_max_size` | = upload + marge | ≥ upload | `php_value` |
| `max_execution_time` | 60 s | 0 – 3600 | `php_value` (+ délai nginx aligné) |
| `max_input_time` | 60 s | -1 – 3600 | `php_value` |
| `max_input_vars` | 4000 | 1000 – 100000 | `php_value` |
| `display_errors` | off | on/off | `php_value` |
| `error_reporting` | « production » | 3 choix prédéfinis | `php_value` |
| `date.timezone` | Europe/Paris | liste PHP | `php_value` |
| `short_open_tag`, `allow_url_fopen` | off / on | on/off | `php_value` |
| `session.gc_maxlifetime` | 1440 | 60 – 604800 | `php_value` |

`php_value` = modifiable ensuite par l'appli (`ini_set`) ou un `.user.ini`, comme sur HestiaCP
(`.user.ini` reste lu).

### 2.2 Isolation (comme HestiaCP, en `php_admin_value` : non contournable)
- `open_basedir` = dossier du site + son dossier `tmp` + `/tmp` + `/usr/share/php` ;
- `upload_tmp_dir` et `session.save_path` = `<site>/tmp` (créé, 0700) ;
- `sendmail_path = /usr/sbin/sendmail -t -i -f noreply@<domaine>` ;
- `error_log = /var/log/php-fpm/<pool>.error.log` (répare le visualiseur existant) ;
- `disable_functions` : voir décision D2.

### 2.3 Pool (admin seulement)
- mode `pm` : ondemand (défaut, comme HestiaCP) / dynamic / static ;
- `max_children` (colonne existante `php_max_workers`), `pm.max_requests`, `process_idle_timeout`,
  `request_terminate_timeout` aligné sur `max_execution_time`.

### 2.4 Directives libres (admin seulement)
Champ « directives supplémentaires » : lignes `clé = valeur`, clé `[a-z0-9_.]+`, valeur sans saut de
ligne ni `[`/`]` ; refus de `extension`, `zend_extension`, `open_basedir`, `disable_functions`,
`auto_prepend_file`… (les clés de sécurité ne bougent que par 2.2). Remplace les « modèles de pool
personnalisés » d'HestiaCP.

### 2.5 Fiabilité
- rendu du pool = fonction pure testée ; écriture atomique avec copie de l'ancien fichier ;
- `php-fpmX.Y -t` avant reload ; échec → ancien pool remis, erreur 400 lisible à l'écran ;
- changement de version : l'ancien pool est supprimé de toutes les autres versions.

### 2.6 Qui peut modifier
- le **propriétaire du site** (rôle client) : 2.1, dans les bornes ;
- l'**admin** : tout, y compris 2.2 (désactivation d'`open_basedir` pour un site précis), 2.3, 2.4.

## 3. Données
Migration : `ALTER TABLE sites ADD COLUMN php_settings JSONB NOT NULL DEFAULT '{}'` (seulement les
valeurs modifiées ; le reste = défauts du code) + `php_isolation BOOLEAN NOT NULL DEFAULT true`.
`php_memory_mb` / `php_max_workers` restent les colonnes de référence (pas de doublon).

## 4. Hors périmètre
- RHEL (pas de pool par site upstream) ; extensions par site (elles restent par version) ;
- un utilisateur Linux par client comme HestiaCP (ce serait le vrai cloisonnement entre clients :
  gros chantier, à traiter séparément si tu en as besoin) ;
- éditeur du `php.ini` global : voir décision D3.

## 5. Tests en VM
1. Site WordPress-like : changer chaque réglage → `phpinfo()` (via curl) montre la valeur.
2. Upload de 100 Mo avec limite 128M : passe ; avec 64M : refusé proprement.
3. `open_basedir` : un script lit `/etc/passwd` et un autre site → refusé ; ses propres fichiers → OK.
4. Directive libre invalide → refusée ; pool cassé simulé → `-t` échoue, ancien pool conservé, site OK.
5. Changement 8.3 → 8.4 : plus aucun pool résiduel en 8.3.
6. Compte client : peut changer `memory_limit`, pas `open_basedir` ni le pool.
7. Sites existants après migration : toujours fonctionnels (contrôle de la décision D1).

## 6. Décisions (validées le 2026-11-14)
- **D1 - Isolation : nouveaux sites seulement.** Les sites existants gardent leur comportement ;
  l'admin l'active site par site. Migration : `php_isolation` et `php_disable_shell` ajoutées avec
  `DEFAULT false` (remplit les lignes existantes), puis `SET DEFAULT true` (nouveaux sites).
- **D2 - Fonctions shell bloquées par défaut** (`exec, system, passthru, shell_exec, proc_open,
  popen`, en `php_admin_value[disable_functions]`) sur les nouveaux sites ; l'admin peut les
  réautoriser pour un site (case `php_disable_shell`). Sites existants : non bloquées (D1).
- **D3 - Éditeur du php.ini global inclus.** Page admin « PHP » (par version installée) :
  - formulaire des réglages principaux (memory_limit, max_execution_time, max_input_time,
    upload_max_filesize, post_max_size, display_errors, error_reporting, date.timezone) +
    éditeur brut de `/etc/php/X.Y/fpm/php.ini` ;
  - **par version** (contrairement à HestiaCP qui recopie un seul fichier sur toutes les versions
    et le CLI) ; le php.ini CLI n'est pas touché ;
  - copie de secours, `php-fpmX.Y -t`, redémarrage, retour automatique à l'ancien fichier si le
    test ou le redémarrage échoue ;
  - les réglages par site (pool) restent prioritaires sur le global : l'interface le signale.
  - Test VM ajouté : modifier memory_limit global 8.3 → visible sur un site sans réglage propre,
    ignoré sur un site qui a le sien ; php.ini cassé → refusé, ancien rétabli, FPM toujours actif.
