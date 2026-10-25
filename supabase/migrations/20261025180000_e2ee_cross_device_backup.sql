-- KMCT Community: store only a password-encrypted E2EE private-key backup.
-- The user's password is never stored. Existing local keys are backed up on next sign-in.
alter table public.profiles
  add column if not exists e2ee_private_key_backup text,
  add column if not exists e2ee_backup_salt text;

comment on column public.profiles.e2ee_private_key_backup is
  'AES-GCM ciphertext of the user E2EE private key, encrypted with a PBKDF2 key derived from the user password; never store plaintext private keys here.';
comment on column public.profiles.e2ee_backup_salt is
  'Random salt used to derive the password-based encryption key for e2ee_private_key_backup.';
