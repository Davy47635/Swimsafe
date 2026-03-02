-- SwimSafe migration: add general beach information fields
-- Safe to run multiple times. Adds nullable columns only.

ALTER TABLE beaches
  ADD COLUMN IF NOT EXISTS address_line1 VARCHAR(160),
  ADD COLUMN IF NOT EXISTS address_line2 VARCHAR(160),
  ADD COLUMN IF NOT EXISTS town VARCHAR(120),
  ADD COLUMN IF NOT EXISTS postcode VARCHAR(20),
  ADD COLUMN IF NOT EXISTS country VARCHAR(60),

  ADD COLUMN IF NOT EXISTS parking_info TEXT,
  ADD COLUMN IF NOT EXISTS facilities TEXT,
  ADD COLUMN IF NOT EXISTS access_notes TEXT,
  ADD COLUMN IF NOT EXISTS safety_notes TEXT,
  ADD COLUMN IF NOT EXISTS emergency_access TEXT,

  ADD COLUMN IF NOT EXISTS maps_url VARCHAR(500),
  ADD COLUMN IF NOT EXISTS website_url VARCHAR(500);