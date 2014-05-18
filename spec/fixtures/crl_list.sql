-- CREATE SCHEMA
CREATE TABLE revoked_serials(
   serial TEXT NOT NULL PRIMARY KEY,
   reason INTEGER,
   revoked_at INTEGER NOT NULL
);
CREATE TABLE crl_number(
  number INTEGER NOT NULL DEFAULT 0
);
INSERT INTO crl_number DEFAULT VALUES;
-- LOAD DATA
INSERT INTO revoked_serials (serial, reason, revoked_at) VALUES ('12345',0,1323983885);
INSERT INTO revoked_serials (serial, reason, revoked_at) VALUES ('12346',null,1323983885);
