-- Defect 5: Policy modified by subsequent migration to become overly permissive
CREATE TABLE "public"."items" (
  id serial PRIMARY KEY,
  name text NOT NULL
);

ALTER TABLE "public"."items" ENABLE ROW LEVEL SECURITY;

-- Initially created with restrictive check
CREATE POLICY "Items write" ON "public"."items"
  FOR UPDATE
  TO authenticated
  USING (auth.uid() IS NOT NULL);

-- Subsequently altered to unconditionally true across all rows
ALTER POLICY "Items write" ON "public"."items"
  USING (true);
