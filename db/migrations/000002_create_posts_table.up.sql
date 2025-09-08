CREATE TABLE "posts" (
  "id" BIGSERIAL PRIMARY KEY,

  "title" VARCHAR(255) NOT NULL,

  "content" TEXT NOT NULL,

  "published_at" TIMESTAMPTZ,

  "created_at" TIMESTAMPTZ NOT NULL DEFAULT (now()),

  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT (now())
);