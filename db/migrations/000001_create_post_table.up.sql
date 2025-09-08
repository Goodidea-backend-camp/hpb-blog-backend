CREATE TYPE post_status AS ENUM ('draft', 'published', 'archived');

CREATE TABLE "posts" (
  "id" BIGSERIAL PRIMARY KEY,
  
  "title" VARCHAR(255) NOT NULL,
  
  "content" TEXT NOT NULL,
  
  "status" post_status NOT NULL DEFAULT 'draft',
  
  "published_at" TIMESTAMPTZ,
  
  "created_at" TIMESTAMPTZ NOT NULL DEFAULT (now()),
  
  "updated_at" TIMESTAMPTZ NOT NULL DEFAULT (now())
);