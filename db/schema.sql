-- The Process database schema (Neon Postgres). Applied automatically by the API on first use.
CREATE TABLE IF NOT EXISTS staff (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  name text NOT NULL,
  pass_hash text NOT NULL,
  role text NOT NULL DEFAULT 'staff' CHECK (role IN ('admin','staff')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS youth (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  first_name text NOT NULL,
  last_name text NOT NULL,
  site text NOT NULL CHECK (site IN ('jdc','stars')),
  pin_hash text NOT NULL,
  consent_on_file boolean NOT NULL DEFAULT false,
  consent_date date,
  guardian_name text,
  guardian_relation text,
  guardian_phone text,
  interests jsonb NOT NULL DEFAULT '[]'::jsonb,
  intake jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS lesson_progress (
  youth_id uuid NOT NULL REFERENCES youth(id) ON DELETE CASCADE,
  lesson int NOT NULL CHECK (lesson BETWEEN 1 AND 8),
  completed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (youth_id, lesson)
);
CREATE TABLE IF NOT EXISTS mentor_visits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  youth_id uuid NOT NULL REFERENCES youth(id) ON DELETE CASCADE,
  staff_id uuid REFERENCES staff(id),
  visited_at timestamptz NOT NULL DEFAULT now(),
  notes text
);
CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  staff_id uuid,
  action text NOT NULL,
  target text,
  at timestamptz NOT NULL DEFAULT now()
);
