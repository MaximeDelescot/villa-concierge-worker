-- Adds an optional WhatsApp/phone number per manager, used to send them a
-- WhatsApp alert (in addition to email) when the concierge can't answer a
-- guest on its own.

ALTER TABLE managers ADD COLUMN phone TEXT;
