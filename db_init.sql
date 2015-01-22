CREATE TABLE IF NOT EXISTS
    users
    (id INTEGER PRIMARY KEY, email VARCHAR UNIQUE NOT NULL,
     password VARCHAR NOT NULL);

CREATE TABLE IF NOT EXISTS
    entries
    (id INTEGER PRIMARY KEY,
    user INTEGER NOT NULL, account VARCHAR NOT NULL,
    username VARCHAR NOT NULL, password VARCHAR NOT NULL);

-- for debugging only
INSERT OR IGNORE INTO users (email, password) VALUES 
      ('dbkats@gmail.com', 'testPass');
