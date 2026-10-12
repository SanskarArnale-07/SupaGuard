-- Migration 2: Table created here, RLS enabled in subsequent migration
CREATE TABLE "public"."audit_logs" (
  id serial PRIMARY KEY,
  action text NOT NULL
);

-- Temporary table that will be dropped in migration 3
CREATE TABLE "public"."temp_staging" (
  id int
);
