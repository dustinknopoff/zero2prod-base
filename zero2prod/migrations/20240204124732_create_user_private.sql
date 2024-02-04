CREATE TABLE user_private (
    user_id uuid PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    phone_number TEXT NOT NULL UNIQUE
);