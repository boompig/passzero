CREATE TABLE IF NOT EXISTS users
    (id SERIAL PRIMARY KEY, email VARCHAR UNIQUE NOT NULL,
     password VARCHAR NOT NULL, salt CHAR(32) NOT NULL);

CREATE TABLE IF NOT EXISTS entries
    (id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL, account VARCHAR UNIQUE NOT NULL,
    username VARCHAR NOT NULL, password VARCHAR NOT NULL,
    padding VARCHAR NOT NULL);