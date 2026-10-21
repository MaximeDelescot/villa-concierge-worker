-- Optional address for a villa. Set at creation (or later in Settings),
-- it powers two things on the frontend: a prefill for the "Location"
-- knowledge item, and detecting whether the villa is in Bali so the
-- Bali-specific suggestion card (EssentialsGroupCard) only appears where
-- it's actually relevant, instead of unconditionally on every villa.
ALTER TABLE villas ADD COLUMN address TEXT;
