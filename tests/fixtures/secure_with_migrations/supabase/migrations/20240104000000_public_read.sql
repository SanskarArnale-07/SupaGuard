-- Migration 4: Intentionally public read-only policy
CREATE TABLE "public"."blog_posts" (
  id serial PRIMARY KEY,
  title text NOT NULL,
  body text NOT NULL
);

ALTER TABLE "public"."blog_posts" ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Public read blog posts" ON "public"."blog_posts"
  FOR SELECT
  TO anon, authenticated
  USING (true);
