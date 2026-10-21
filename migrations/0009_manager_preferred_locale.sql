-- Lets a manager pin a fixed language for reading guest conversations,
-- instead of always inferring it from their browser's Accept-Language
-- header (unreliable across devices / shared browsers). NULL means "not
-- set" -- the backend falls back to Accept-Language, same as before this
-- column existed.
ALTER TABLE managers ADD COLUMN preferred_locale TEXT;
