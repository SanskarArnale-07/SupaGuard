-- Defect 1: Table without RLS in API-exposed schema (public)
CREATE TABLE "public"."unprotected_orders" (
  id serial PRIMARY KEY,
  customer_id uuid NOT NULL,
  total_amount numeric NOT NULL
);
