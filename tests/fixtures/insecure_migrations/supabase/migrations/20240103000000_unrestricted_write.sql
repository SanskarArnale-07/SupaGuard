-- Defect 3: Unrestricted INSERT policy for anonymous users
CREATE TABLE "public"."feedback" (
  id serial PRIMARY KEY,
  message text NOT NULL
);

ALTER TABLE "public"."feedback" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anon open insert" ON "public"."feedback"
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- Defect 4: Unrestricted ALL policy for public role (includes write)
CREATE TABLE "public"."documents" (
  id serial PRIMARY KEY,
  content text NOT NULL
);

ALTER TABLE "public"."documents" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public open access" ON "public"."documents"
  FOR ALL
  TO public
  USING (true);
