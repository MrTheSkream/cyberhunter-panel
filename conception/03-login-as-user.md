# Fonctionnalité 3 - Se connecter en tant qu'utilisateur (validée)

## 1. Point de départ

**CyberHunter - Panel aujourd'hui** :
- session = JWT HS256 de 2 h dans le cookie `token` (HttpOnly, SameSite=Lax), avec `sub`, `email`,
  `role`, `jti` ; chaque session a une ligne `user_sessions` (révocation) ; le rôle du jeton fait foi
  pendant toute sa durée ;
- l'admin gère les comptes (`/api/users` : créer, rôle, suspendre, réinitialiser mot de passe / 2FA,
  supprimer) mais **ne peut pas voir le panel comme le client le voit** ; rien de tel n'existe ;
- toutes les vérifications de propriété (sites, piles, serveurs) se basent sur `sub` : un jeton dont
  `sub` = le client voit exactement ce que voit le client.

**HestiaCP** :
- icône « Se connecter en tant que » dans la liste des utilisateurs, admin seulement ;
- la session de l'admin est gardée de côté (`$_SESSION['look']`) ; « Déconnexion » ramène à l'admin ;
- l'admin agit comme l'utilisateur, **sans restriction** (il peut changer son mot de passe, ses clés…) ;
- l'utilisateur n'est pas prévenu ; le journal note les actions au nom de l'utilisateur.

## 2. Ce qu'on fait

### 2.1 Démarrer
- Bouton **« Se connecter en tant que »** sur chaque ligne de la page Utilisateurs (bureau et mobile),
  avec confirmation. Masqué pour soi-même, les autres admins et les comptes suspendus (décision D3).
- `POST /api/users/{id}/impersonate` (admin) :
  - refuse : soi-même, un autre admin (même garde que `is_other_admin`), compte suspendu (D3) ;
  - applique la liste d'IP autorisées du panel (comme toutes les portes qui créent une session) ;
  - **ne demande pas** le mot de passe ni la 2FA du client (c'est le but) ; la 2FA de l'admin a déjà
    été passée à sa propre connexion ;
  - crée un jeton pour le client : `sub`, `email`, `role` du client + **`imp_by` = id de l'admin** et
    `imp_email`, durée **1 h** (non prolongeable) ; ligne `user_sessions` avec `impersonator_id` ;
  - le cookie de l'admin est **mis de côté** dans un cookie `token_admin` (HttpOnly,
    `Path=/api/auth/impersonate`) : il n'est envoyé qu'à la route de retour, jamais aux autres requêtes ;
  - journal : `impersonate.start` dans le journal de sécurité (immuable) et le journal d'activité.

### 2.2 Pendant
- Bandeau permanent en haut de tous les thèmes : « Connecté en tant que **client@x** (par admin@y) -
  **Revenir à mon compte** ». `GET /api/auth/me` renvoie `impersonated_by`.
- L'admin voit et fait ce que fait le client (sites, mails, bases, fichiers, PHP…), dans les droits du
  client (un client ne voit pas le menu Admin, etc.).
- **Bloqué** pendant la session (403 « Indisponible en mode connexion en tant que ») - ce qui
  donnerait à l'admin un accès durable au compte ou toucherait à sa sécurité :
  - mot de passe, 2FA (activer, désactiver, codes de secours), passkeys (ajouter, renommer, supprimer) ;
  - clés API (créer, faire tourner, supprimer) : une clé créée survivrait à la session ;
  - révocation de sessions, export RGPD des données, export du coffre de secrets, acceptation
    d'invitation d'équipe ;
  - côté interface, ces cartes de « Mon compte » sont grisées avec l'explication ;
  - (différence assumée avec HestiaCP, qui ne bloque rien).
- **Traçabilité** : chaque action est journalisée au nom du client **avec la mention de l'admin**
  (« admin@y en tant que client@x »). Mécanisme : un middleware lit `imp_by` et le place dans le
  contexte de la requête ; `log_activity` et `audit_log` l'ajoutent automatiquement (nouvelles colonnes
  `impersonator_id` / `impersonator_email`) - aucun des ~100 appels existants n'est à modifier.

### 2.3 Terminer
- « Revenir à mon compte » → `POST /api/auth/impersonate/stop` : jeton client mis en liste noire,
  ligne `user_sessions` supprimée, cookie admin restauré depuis `token_admin` **s'il est encore valide**
  (sinon retour à la page de connexion) ; `impersonate.stop` journalisé. Rechargement complet de la
  page (le serveur sélectionné est réinitialisé).
- « Déconnexion » pendant la session = même chose que « Revenir ».
- Fin automatique au bout d'1 h, ou si le client est suspendu/supprimé (révocation existante), ou si
  l'admin est rétrogradé/suspendu (ses sessions « en tant que » sont révoquées avec les siennes).

### 2.4 Sécurité - ce qui est volontairement refusé
- Le jeton client **ne peut pas** fabriquer une session admin : le retour réutilise le vrai cookie de
  l'admin, il n'en crée pas un nouveau à partir d'`imp_by`. Un jeton client volé ne donne que le client.
- Pas d'imbrication (impossible de démarrer depuis une session « en tant que »).
- Pas depuis une clé API : il faut une session de navigateur.

## 3. Données
Migration :
- `user_sessions.impersonator_id UUID NULL REFERENCES users(id) ON DELETE CASCADE` ;
- `activity_logs.impersonator_id UUID NULL`, `activity_logs.impersonator_email TEXT NULL` ;
- `security_audit_log` : remplir la colonne existante `actor_user_id` (jamais utilisée jusqu'ici).
Jeton : champs `imp_by: Option<Uuid>`, `imp_email: Option<String>` (`#[serde(default)]`, comme `key_id`).

## 4. Hors périmètre
- Mode lecture seule (« voir sans pouvoir modifier ») : possible plus tard.
- Connexion en tant qu'un autre admin : refusée.

## 5. Tests en VM
1. Admin → « Se connecter en tant que » client : bandeau, il voit **seulement** les sites du client,
   pas le menu Admin ; une route admin (`/api/users`) répond 403.
2. Action du client (ex. réglage PHP) → journal : « admin@y en tant que client@x ».
3. Mot de passe, 2FA, passkey, clé API, export → 403 ; cartes grisées.
4. « Revenir » → admin à nouveau ; le jeton client est refusé ensuite (liste noire).
5. Refus : soi-même, autre admin, compte suspendu, depuis une clé API, depuis une session « en tant que ».
6. Fin : jeton d'1 h (durée réduite en test) ; client suspendu pendant la session → session coupée.
7. Le cookie `token_admin` n'est envoyé qu'à la route de retour (vérifié dans les en-têtes).
Note : ces tests demandent **un compte client de test dans la VM** (avec ton accord) - ce qui permettra
aussi de tester la vue client des réglages PHP restée en attente.

## 6. Décisions (validées le 2026-11-14)
- **D1 - Admin seulement** (comme HestiaCP). Les revendeurs n'y ont pas accès.
- **D2 - Session marquée, pas de mail** : la session apparaît dans la liste des sessions du client
  comme « Admin admin@y » (via `impersonator_id`) ; tout est journalisé ; aucun mail n'est envoyé.
- **D3 - Comptes suspendus refusés.**
- **D4 - Actions sensibles bloquées** pendant la session (liste du 2.2) : mot de passe, 2FA, passkeys,
  clés API, sessions, exports, invitation d'équipe.
