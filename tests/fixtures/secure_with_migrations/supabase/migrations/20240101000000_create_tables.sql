-- Migration 1: Table created with RLS enabled immediately
CREATE TABLE "public"."profiles" (
  id uuid PRIMARY KEY,
  username text NOT NULL
);

ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own profile" ON "public"."profiles"
  FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON "public"."profiles"
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);
