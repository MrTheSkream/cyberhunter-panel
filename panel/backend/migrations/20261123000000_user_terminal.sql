-- Fonctionnalité 9 : terminal utilisateur (shell non root dans une session tmux persistante).
-- Voir conception/09-terminal-utilisateur.md (§5) et 09-terminal-utilisateur-contrats.md (B-1).
--
-- Une ligne par compte panel relié à un utilisateur Linux. Le login vient
-- uniquement de cette table : la demande de ticket n'a aucun paramètre
-- d'utilisateur. `uid` est celui relevé par l'agent à l'enregistrement, et
-- l'agent le revérifie à chaque ouverture.

CREATE TABLE IF NOT EXISTS user_linux_accounts (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  linux_user text NOT NULL UNIQUE,
  uid integer NOT NULL CHECK (uid >= 1000 AND uid < 60000),
  autostart_command text NULL DEFAULT 'claude',
  record boolean NOT NULL DEFAULT false,
  created_by uuid NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now());

-- Interrupteur « User terminal » (réglage inversé, comme server_terminal_disabled).
INSERT INTO settings (key, value) VALUES ('user_terminal_disabled', 'false')
  ON CONFLICT (key) DO NOTHING;
