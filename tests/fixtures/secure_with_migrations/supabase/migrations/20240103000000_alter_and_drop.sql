-- Migration 3: Enable RLS on audit_logs and drop temp_staging
ALTER TABLE "public"."audit_logs" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role only" ON "public"."audit_logs"
  FOR SELECT
  TO authenticated
  USING (auth.jwt() ->> 'role' = 'service_role');

-- Drop temporary table
DROP TABLE "public"."temp_staging";

-- Comments containing SQL fragments resembling unsafe statements
-- ALTER TABLE "public"."profiles" DISABLE ROW LEVEL SECURITY;
-- CREATE POLICY "open_hack" ON "public"."profiles" FOR ALL USING (true);
/*
  ALTER TABLE "public"."profiles" DISABLE ROW LEVEL SECURITY;
*/

-- Table with string literal resembling unsafe SQL
CREATE TABLE "public"."notes" (
  id int PRIMARY KEY,
  content text DEFAULT 'ALTER TABLE "public"."notes" DISABLE ROW LEVEL SECURITY'
);

ALTER TABLE "public"."notes" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Notes restricted" ON "public"."notes"
  FOR ALL
  TO authenticated
  USING (auth.uid() IS NOT NULL);

-- Non-exposed internal schema table (missing RLS is not flagged because private_schema is not in api.schemas)
CREATE TABLE "private_schema"."internal_keys" (
  id int PRIMARY KEY
);
