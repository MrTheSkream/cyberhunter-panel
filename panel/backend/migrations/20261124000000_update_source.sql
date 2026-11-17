-- L'annonce stockée vient peut-être du dépôt amont : on l'efface.
DELETE FROM settings WHERE key IN
  ('update_available_version', 'update_release_notes', 'update_release_url');
