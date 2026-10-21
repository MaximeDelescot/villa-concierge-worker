-- One optional cover photo per villa, shown on its dashboard card and
-- detail page instead of a generic placeholder icon. Stored in R2 like
-- knowledge-item photos (see uploadKnowledgePhoto); this column just
-- holds the resulting /img/<key> URL, or NULL if none was uploaded yet.
ALTER TABLE villas ADD COLUMN cover_photo_url TEXT;
