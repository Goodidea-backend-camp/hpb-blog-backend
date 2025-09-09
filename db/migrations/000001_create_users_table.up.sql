-- 本 Migration 僅為測試用途，實際使用時請依照資料庫結構調整，勿直接套用

CREATE TABLE IF NOT EXISTS users(
   user_id serial PRIMARY KEY,
   username VARCHAR (50) UNIQUE NOT NULL,
   hashed_password VARCHAR (60) NOT NULL,
   email VARCHAR (300) UNIQUE NOT NULL
);
