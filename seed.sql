INSERT INTO admin_credentials
  (name, name_key, password_algo, password_iters, password_salt,
   password_hash, created_at, updated_at)
VALUES
  ('christian belon', 'christian belon', 'pbkdf2-sha256', 100000,
   'QU3PNsYPF7XEz+lk14VxkQ==', 'Vh9RS+qQ4lGBccKPwfTNcuxY8nZ82zrzl+sS/f6wQmk=', 1795594243, 1795594243)
ON CONFLICT (name_key) DO UPDATE SET
  name           = excluded.name,
  password_algo  = excluded.password_algo,
  password_iters = excluded.password_iters,
  password_salt  = excluded.password_salt,
  password_hash  = excluded.password_hash,
  updated_at     = excluded.updated_at;
