# Fonctionnalité 3 - Contrats d'interface (se connecter en tant qu'utilisateur)

Référence : `03-login-as-user.md` (décisions D1-D4). Ce fichier fixe ce que le backend et le frontend
s'échangent, pour qu'ils puissent être écrits en parallèle.

## A. Jeton (`panel/backend/src/auth.rs`)
```rust
pub struct Claims { /* existant */
    #[serde(default)] pub imp_by: Option<Uuid>,     // id de l'admin qui agit
    #[serde(default)] pub imp_email: Option<String>,// son e-mail (affichage, journaux)
}
```
- Tous les constructeurs existants de `Claims` mettent `None` (API keys, login, 2FA, passkey, OAuth, tests).
- Helper `pub fn deny_if_impersonating(claims: &Claims) -> Result<(), ApiError>` :
  403 `{"error": "Not available while logged in as another user", "code": "impersonation_forbidden"}`.

## B. Routes

### B1. `POST /api/users/{id}/impersonate` (AdminUser)
- Refus :
  - 400 si la session courante n'est pas un cookie de navigateur JWT : `key_id` présent, ou pas de
    cookie `token` dans la requête ;
  - 400 si la session est déjà `imp_by` ;
  - 400 si `id` est soi-même ;
  - 403 si la cible est admin ;
  - 403 si la cible est `suspended` ;
  - 404 si la cible est inconnue.
- `enforce_panel_ip_allowlist` comme au login.
- Jeton cible : `sub/email/role` de la cible (rôle lu en base), `imp_by/imp_email` de l'admin,
  `iat` = maintenant, `exp` = maintenant + `IMPERSONATION_TTL_SECS` (3600, constante), nouveau `jti`.
  INSERT `user_sessions (user_id, jti, ip_address, user_agent, impersonator_id)`.
- Deux en-têtes `Set-Cookie` (même drapeau `Secure` que le login) :
  - `token=<jeton cible>; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600` ;
  - `token_admin=<valeur brute du cookie token de l'admin>; Path=/api/auth/impersonate; HttpOnly;
    SameSite=Strict; Max-Age=<secondes restantes du jeton admin>`.
- Journaux :
  - `security_hardening::audit_log("impersonate.start", ...)` avec l'admin comme acteur, la cible
    comme target, severity "warning" ;
  - `log_activity` action `user.impersonate`.
- Réponse 200 : `{ "user": {id,email,role}, "impersonated_by": {id,email}, "expires_at": <unix s> }`.

### B2. `POST /api/auth/impersonate/stop` (AuthUser, `imp_by` requis sinon 400)
- Jeton courant : jti en liste noire (mémoire + `token_blacklist`), ligne `user_sessions` supprimée.
- Cookie `token_admin` : décodé et validé comme dans `AuthUser` :
  - signature, `exp`, pas en liste noire, `iat >= sessions_revoked_at` ;
  - **en plus** : `sub == imp_by`, utilisateur en base toujours `role='admin'`.
- Si valide : `Set-Cookie token=<token_admin>; Path=/; HttpOnly; SameSite=Lax; Max-Age=<restant>`.
  Sinon : `token=; Max-Age=0`.
- Toujours : `token_admin=; Path=/api/auth/impersonate; Max-Age=0`.
- Journal : `impersonate.stop`.
- Réponse : `{ "restored": bool }`. Si `restored` vaut false, le frontend va sur `/login`.
- `POST /api/auth/logout` pendant une session « en tant que » se comporte exactement comme `stop`
  (même réponse, le frontend n'a qu'un chemin).

### B3. `GET /api/auth/me`
Ajoute `"impersonated_by": {"id","email"} | null` et `"impersonation_expires_at": <unix s> | null`.

### B4. Routes bloquées (`deny_if_impersonating` en tête du handler)
- **Mot de passe :** `POST /api/auth/change-password`.
- **2FA :** `/api/auth/2fa/setup`, `/2fa/enable`, `/2fa/disable`, `/2fa/recovery-codes`.
  `/2fa/status` reste autorisé (lecture).
- **Passkeys :** register begin et complete, `PUT` et `DELETE /api/auth/passkeys/{id}`.
- **Clés API :** `POST /api/api-keys`, `DELETE /api/api-keys/{id}`, `POST /api/api-keys/{id}/rotate`.
  `GET` reste autorisé.
- **Sessions :** `DELETE /api/auth/sessions/{id}`.
- **Exports :** `GET /api/auth/export-my-data`, export du coffre de secrets.
- **Équipes :** acceptation d'invitation.
- **Défense en profondeur :** `POST /api/users/{id}/impersonate` (déjà refusé par le rôle).

### B5. `GET /api/auth/sessions`
Chaque élément ajoute `"impersonator_email": string | null`, via une jointure sur
`user_sessions.impersonator_id`.

### B6. Révocation
`revoke_all_user_sessions(state, user_id)` révoque aussi les lignes `user_sessions` dont
`impersonator_id = user_id`. Effet : un admin suspendu, rétrogradé ou supprimé perd ses sessions
« en tant que ».

## C. Journaux : attribution automatique
- **Contexte de requête :** `tokio::task_local! { pub static IMPERSONATOR: Option<(Uuid, String)> }`
  dans `services/activity.rs`.
- **Middleware axum** (`main.rs`, sur le routeur API) : décode le cookie `token` ou le Bearer JWT
  (pas `dp_`), sans autre vérification (l'extracteur le fait). Si `imp_by` est présent, il exécute
  `IMPERSONATOR.scope(Some(..), next.run(req))`, sinon `scope(None, ..)`.
- **Écriture des journaux :** `log_activity*` et `security_hardening::audit_log` lisent
  `IMPERSONATOR.try_with(|v| v.clone()).ok().flatten()` et écrivent les nouvelles colonnes. Les tâches
  `tokio::spawn` perdent le task-local : celles qui journalisent pour la requête capturent la valeur
  avant le spawn, au moins pour le login et le start/stop.
- `GET /api/activity` renvoie `impersonator_email` par ligne. La page Journaux affiche
  « admin@y en tant que client@x ».

## D. Migration `panel/backend/migrations/20261117000000_impersonation.sql`
```sql
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS impersonator_id UUID NULL REFERENCES users(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_user_sessions_impersonator ON user_sessions(impersonator_id) WHERE impersonator_id IS NOT NULL;
ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS impersonator_id UUID NULL;
ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS impersonator_email TEXT NULL;
ALTER TABLE security_audit_log ADD COLUMN IF NOT EXISTS impersonator_email TEXT NULL;
```
Le trigger d'immutabilité de `security_audit_log` bloque UPDATE et DELETE, pas ALTER : à vérifier.

## E. Frontend
- **`context/AuthContext.tsx` :**
  - `user` porte `impersonated_by?: {id,email} | null` et `impersonation_expires_at?: number | null` ;
  - nouvelle fonction `stopImpersonation()` : POST `/auth/impersonate/stop`, supprime
    `localStorage["dp-active-server"]`, puis `window.location.href = restored ? "/" : "/login"` ;
  - `logout()` appelle `stopImpersonation()` si `impersonated_by` est renseigné.
- **`components/ImpersonationBanner.tsx` :** bandeau fixe en haut, visible si `impersonated_by`.
  - Texte : « Connecté en tant que {email} (par {admin}) - expire à HH:MM » + bouton
    « Revenir à mon compte ».
  - Inséré dans les 4 thèmes : CommandLayout, GlassLayout, AtlasLayout, NexusLayout.
- **`pages/Users.tsx` :** bouton « Se connecter en tant que » sur les lignes bureau et mobile,
  masqué si `isSelf`, `role === "admin"` ou `role === "suspended"`.
  - Confirmation : « Vous allez agir comme {email} pendant 1 h au plus. Tout est journalisé. »
  - Puis POST, suppression de `dp-active-server` et `window.location.href = "/"`.
- **`components/AccountSecurity.tsx` / `pages/Account.tsx` :** si `impersonated_by` est renseigné,
  les cartes mot de passe, 2FA, passkeys, clés API, révocation de session et export sont désactivées
  avec la mention « Indisponible en mode connexion en tant que ».
- **Liste des sessions :** badge « Admin {impersonator_email} ».
- **Journaux d'activité :** colonne utilisateur `"{impersonator_email} en tant que {user_email}"` si
  `impersonator_email` est renseigné.
- **`api.ts` :** une réponse 403 `code === "impersonation_forbidden"` affiche simplement l'erreur
  (pas de redirection).
