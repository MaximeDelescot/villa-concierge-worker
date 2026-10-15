-- Knowledge items move from a single `photo` field to up to 4 photos,
-- each with an optional caption, stored as JSON in `photos_json`.
-- The old `photo` column is left in place (unused going forward) rather
-- than dropped, to keep this migration low-risk.

ALTER TABLE knowledge_items ADD COLUMN photos_json TEXT NOT NULL DEFAULT '[]';

UPDATE knowledge_items
SET photos_json = json_array(json_object('url', photo, 'caption', NULL))
WHERE photo IS NOT NULL AND photo != '';
