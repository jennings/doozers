-- Whose SSH keys a workspace gets (doozers_core::ssh): the user the creating turn named, or NULL
-- for none. A direct conversation's workspace gets its user's keys, a runtime job run's its
-- creator's, and a group session's or a config job run's gets none. A workspace keeps its key
-- user for its whole life, and a reset keeps it for the new workspace.
--
-- Workspaces created before this column have no recorded creating turn. A conversation's workspace
-- takes the user of the newest `direct` session of its key; a job run's stays NULL, since runs
-- don't outlive the process.
ALTER TABLE workspaces ADD COLUMN key_user TEXT CHECK (key_user <> '');

UPDATE workspaces
SET key_user = (
    SELECT sessions.user_id
    FROM sessions
    WHERE sessions.kind = 'direct'
      AND sessions.user_id IS NOT NULL
      AND sessions.agent = workspaces.agent
      AND sessions.channel = workspaces.channel
      AND sessions.conversation = workspaces.conversation
    ORDER BY sessions.started_at DESC, sessions.id DESC
    LIMIT 1
)
WHERE job_session IS NULL;
