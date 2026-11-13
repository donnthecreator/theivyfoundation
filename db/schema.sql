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

-- Student self sign-up and guardian waiver (added 2026-11-11)
ALTER TABLE youth ADD COLUMN IF NOT EXISTS guardian_email text;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE youth ADD COLUMN IF NOT EXISTS waiver_token_hash text;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS waiver_signed_at timestamptz;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS waiver_signer text;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS waiver_relation text;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS waiver_method text;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS app_state jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS failed_logins int NOT NULL DEFAULT 0;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS locked_until timestamptz;
ALTER TABLE youth ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS youth_name_idx ON youth (lower(first_name), lower(last_name));
CREATE UNIQUE INDEX IF NOT EXISTS youth_waiver_token_idx ON youth (waiver_token_hash) WHERE waiver_token_hash IS NOT NULL;

-- Mentor assignments and partner (employer) access, with guardian consent (added 2026-11-11)
ALTER TABLE staff DROP CONSTRAINT IF EXISTS staff_role_check;
ALTER TABLE staff ADD CONSTRAINT staff_role_check CHECK (role IN ('admin','staff','partner'));
CREATE TABLE IF NOT EXISTS staff_youth (
  staff_id uuid NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
  youth_id uuid NOT NULL REFERENCES youth(id) ON DELETE CASCADE,
  guardian_consent_at timestamptz,
  guardian_consent_by text,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (staff_id, youth_id)
);

-- God's Sons (GS) parent sign-ups from the public invite link (added 2026-11-11)
CREATE TABLE IF NOT EXISTS gs_signups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_name text NOT NULL,
  parent_relation text NOT NULL,
  parent_phone text NOT NULL,
  parent_email text,
  contact_pref text,
  kid_first text NOT NULL,
  kid_last text NOT NULL,
  kid_age int,
  kid_grade text,
  kid_school text,
  shirt_size text,
  interests jsonb NOT NULL DEFAULT '[]'::jsonb,
  favorite_team text,
  food_notes text,
  transport text,
  goals text,
  consent_program boolean NOT NULL DEFAULT false,
  consent_messages boolean NOT NULL DEFAULT false,
  media_ok boolean NOT NULL DEFAULT false,
  ref text,
  status text NOT NULL DEFAULT 'new',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Admin-viewable PIN, encrypted at rest (added 2026-11-13)
ALTER TABLE youth ADD COLUMN IF NOT EXISTS pin_enc text;
