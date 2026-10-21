-- "Beaches" was too Bali-specific for a category meant to generalize to
-- any destination (mountains, countryside...). Renamed to "attractions"
-- (Points of interest) in the code; this updates any knowledge items
-- already saved under the old category id so they don't silently
-- disappear from the Knowledge base tab. A no-op if none exist yet.
UPDATE knowledge_items SET category = 'attractions' WHERE category = 'beaches';
