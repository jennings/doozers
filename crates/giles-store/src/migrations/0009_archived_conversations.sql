-- Conversations their user archived: the web chat list leaves them out and lists them under
-- "Archived chats". A conversation is every keyed session with one channel instance and
-- conversation id, whatever the agent, so a row is keyed by the two and outlives `/new`. It has
-- no foreign key: there is no conversations table. Deleting the conversation deletes the row.
CREATE TABLE archived_conversations (
    channel      TEXT    NOT NULL CHECK (channel <> ''),
    conversation TEXT    NOT NULL CHECK (conversation <> ''),
    archived_at  INTEGER NOT NULL,
    PRIMARY KEY (channel, conversation)
) STRICT, WITHOUT ROWID;
