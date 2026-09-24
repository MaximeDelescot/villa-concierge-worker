-- Stores the guest's detected browser language on each conversation, so a
-- manager's manual reply can always be translated into it automatically
-- (see chat() and addManagerReply() in src/worker.js).
ALTER TABLE conversations ADD COLUMN guest_locale TEXT;
