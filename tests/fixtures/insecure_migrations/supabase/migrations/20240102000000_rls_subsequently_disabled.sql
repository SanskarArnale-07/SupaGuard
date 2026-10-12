-- Defect 2: Table has RLS enabled, but subsequently disabled in final state
CREATE TABLE "public"."accounts" (
  id serial PRIMARY KEY,
  balance numeric NOT NULL
);

ALTER TABLE "public"."accounts" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."accounts" DISABLE ROW LEVEL SECURITY;
