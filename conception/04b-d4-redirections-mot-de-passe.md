# D4 - Redirections et mots de passe effacés par une reconstruction du vhost (à valider)

## 1. Constat (code actuel)
- Les écrans « Redirects » et « Password protection » écrivent `/etc/nginx/redirects/<d>.conf`
  et `/etc/nginx/auth/<d>.conf`, puis **insèrent à la main** une ligne `include` avant la dernière `}`
  du vhost (`routes/nginx.rs`, `add_redirect` et `password_protect`).
- Toute reconstruction du vhost (version PHP, SSL, IP, bascule Apache, WAF, renommage…) repart
  des modèles, qui ne contiennent pas ces `include` : **les redirections et les protections
  disparaissent sans message**. Les fichiers restent sur le disque et l'écran les affiche encore.
- **Défaut plus grave repéré en lisant le code : la protection par mot de passe ne protège pas le PHP.**
  Elle crée `location /chemin { auth_basic …; try_files $uri $uri/ =404; }` :
  - en mode nginx, `/chemin/x.php` est pris par la `location ~ \.php$` (les regex passent avant un
    préfixe simple) : **le script s'exécute sans mot de passe** ;
  - en mode Apache, `/chemin/x.php` reste dans ce bloc et `try_files` sert le fichier tel quel :
    **le code source PHP est téléchargeable** (après mot de passe) au lieu d'être exécuté ;
  - protéger `/` crée un second `location /` : `nginx -t` échoue.

## 2. Correction proposée
1. **Les modèles incluent eux-mêmes** les deux fichiers quand ils existent, dans le bloc `server`
   qui sert le site (443 avec SSL, 80 sinon). Plus aucune insertion à la main ; une reconstruction
   les garde toujours. Les vhosts existants sont corrigés à leur prochaine reconstruction, et au
   démarrage de l'agent (même principe que pour open_basedir) pour les sites qui ont l'un de ces fichiers.
2. **Protection par mot de passe réécrite au niveau du `server`** au lieu de blocs `location` :
   ```nginx
   set $cyb_auth off;
   if ($uri ~ "^/admin(/|$)") { set $cyb_auth "Restricted"; }   # une ligne par chemin protégé
   if ($uri ~ "^/\.well-known/acme-challenge/") { set $cyb_auth off; }
   auth_basic $cyb_auth;
   auth_basic_user_file /etc/nginx/htpasswd/<d>;
   ```
   S'applique à **toute** requête sous le chemin (statique, PHP-FPM, Apache, proxy), protège `/`
   sans conflit, laisse passer les validations Let's Encrypt.
   Les fichiers `auth/<d>.conf` existants (ancien format) sont relus et réécrits au nouveau format.
3. Petits correctifs au passage : écriture atomique des deux fichiers, retour arrière si `nginx -t`
   échoue aussi pour le mot de passe (aujourd'hui seulement pour les redirections), retrait d'une
   redirection qui teste la config avant de recharger.

## 3. Tests en VM
1. Redirection + mot de passe sur un site, puis changement de version PHP, bascule Apache/nginx,
   WAF, renommage : les deux tiennent.
2. `/admin/x.php` protégé : 401 sans mot de passe, exécuté avec (modes nginx et Apache).
3. Protection de `/` : `nginx -t` passe, tout le site demande le mot de passe sauf
   `/.well-known/acme-challenge/`.
4. Site existant avec l'ancien format : après mise à jour de l'agent, protection et redirections
   présentes et au nouveau format.
