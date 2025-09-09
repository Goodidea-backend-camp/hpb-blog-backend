-- 本 Migration 僅為測試用途，實際使用時請依照資料庫結構調整，勿直接套用

CREATE TABLE "posts" (
  "id" BIGSERIAL PRIMARY KEY,

  "title" VARCHAR(255) NOT NULL,

  "content" TEXT NOT NULL,

  "published_at" TIMESTAMPTZ,

  "created_at" TIMESTAMPTZ NOT NULL DEFAULT (now()),

  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT (now())
);