-- Local development data: two customers (passwords alice-dev-pw and bob-dev-pw).
INSERT INTO users (id, username, password_hash) VALUES
  (1, 'alice', 'pbkdf2:sha256:600000$bb1d651d0ed37ff9$24a2249c7806486f1bf5e96c0e8c69988aeadd37043cc4742fba6254215b1cf9'),
  (2, 'bob', 'pbkdf2:sha256:600000$2b3a609d17c0822e$cab9dd77bffc1753071904d96f8a836258a3348a54bb9f4c1f39ccc1e2781e0e');
