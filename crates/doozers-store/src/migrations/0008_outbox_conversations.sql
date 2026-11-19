-- An outbox row goes either to an identity or into a conversation. `target` says which:
--
-- - 'recipient': `recipient` is an identity, `<namespace>:<native id>`, which the core routes to
--   the channel instance owning its namespace at each attempt (every row before this migration).
-- - 'conversation': `recipient` is a conversation id on the channel instance `instance`, which the
--   core replies into: a runtime job's reply, sent to the conversation it was scheduled in.
ALTER TABLE outbox ADD COLUMN target TEXT NOT NULL DEFAULT 'recipient'
    CHECK (target IN ('recipient', 'conversation'));
