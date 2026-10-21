-- Tracks which items of the curated "Bali essentials" checklist a
-- manager has explicitly handled (added info for, or marked as not
-- applicable to their villa), so the proactive checklist in the
-- Knowledge base tab stops suggesting something already dealt with.
-- NULL/empty means nothing dismissed yet. Stored as a JSON array of
-- essential keys, e.g. ["drinking_water","scooter_rental"].
ALTER TABLE villas ADD COLUMN checklist_dismissed TEXT;
