-- Per-channel notification preferences for managers: lets each manager
-- turn email and/or WhatsApp alerts on or off independently. Both default
-- to on, matching the behavior before this migration.

ALTER TABLE managers ADD COLUMN notify_email INTEGER NOT NULL DEFAULT 1;
ALTER TABLE managers ADD COLUMN notify_whatsapp INTEGER NOT NULL DEFAULT 1;
