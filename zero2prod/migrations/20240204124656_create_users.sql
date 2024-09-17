CREATE TABLE users (
    user_id uuid PRIMARY KEY,
    user_name TEXT NOT NULL,
    preferred_name TEXT NOT NULL,
    password_hash TEXT NOT NULL
);


INSERT INTO users (user_id, user_name,preferred_name, password_hash)
VALUES (
        '45f07f34-6967-453a-95da-712461c732ae',
        'admin',
        'admin',
        '$argon2id$v=19$m=15000,t=2,p=1$H/unjuDN6hj4FT/XcJHHZg$Y4y9clzdbZtlNp5ueVT0Sq0PDfFbrlyp8gtuxd42bAk'
);
