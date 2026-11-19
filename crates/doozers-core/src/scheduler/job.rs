//! What the scheduler runs: config jobs from `agent.toml` and runtime jobs from the `jobs` table,
//! in one shape.

use doozers_store::{JobKey, RuntimeJob, SessionKey};
use doozers_types::{AgentId, ConversationId, Timestamp, UserId};
use serde::{Deserialize, Serialize};

use super::schedule::When;
use crate::config::{ActiveHours, AskTo, Job, JobPrompt, JobSession, ModelRef, parse_cron};

/// A job, config or runtime.
#[derive(Debug, Clone)]
pub struct JobDef {
    /// Its `job_runs` key.
    pub key: JobKey,
    /// The agent it runs on.
    pub agent: AgentId,
    /// A runtime job's creator: the turn's requester, and the user it delivers to. `None` for a
    /// config job, which has no requester and delivers to the owner.
    pub creator: Option<UserId>,
    /// The conversation a runtime job was scheduled in, where it runs and replies. `None` for a
    /// config job and one scheduled on the web jobs page: those use the user's default identity.
    pub conversation: Option<JobConversation>,
    /// Times before this are never made up as missed: when a runtime job was created, or last
    /// edited or switched back on. `None` for a config job.
    pub since: Option<Timestamp>,
    /// A runtime job that is switched off: it stays stored but doesn't run.
    pub disabled: bool,
    /// When it fires.
    pub when: When,
    /// Which session it runs in.
    pub session: JobSession,
    /// Wait while a turn runs in the user's DM.
    pub idle_only: bool,
    /// Run only inside these hours, in the job's time zone.
    pub active_hours: Option<ActiveHours>,
    /// The model; `None`: the agent's.
    pub model: Option<ModelRef>,
    /// The prompt.
    pub prompt: JobPrompt,
    /// Who answers approvals of `ask` tools; `None`: they're denied.
    pub ask_to: Option<AskTo>,
    /// For isolated runs, how many of the DM's latest messages the prompt includes.
    pub dm_excerpt: Option<u32>,
}

impl JobDef {
    /// Config job `job` of `agent`.
    pub fn from_config(agent: &AgentId, job: &Job) -> Self {
        Self {
            key: JobKey::Config(job.id.clone()),
            agent: agent.clone(),
            creator: None,
            conversation: None,
            since: None,
            disabled: false,
            when: When::Cron(Box::new(job.cron.clone())),
            session: job.session,
            idle_only: job.idle_only,
            active_hours: job.active_hours,
            model: job.model.clone(),
            prompt: job.prompt.clone(),
            ask_to: job.ask_to,
            dm_excerpt: job.dm_excerpt,
        }
    }

    /// A runtime job, from its stored spec ([`RuntimeSpec`]).
    ///
    /// # Errors
    ///
    /// Why the spec is unusable.
    pub fn from_runtime(job: &RuntimeJob) -> Result<Self, String> {
        let spec: RuntimeSpec = serde_json::from_value(job.spec.clone())
            .map_err(|error| format!("invalid job spec: {error}"))?;
        Ok(Self {
            key: JobKey::Runtime(job.id),
            agent: job.agent.clone(),
            creator: Some(job.creator.clone()),
            conversation: spec.conversation.clone(),
            since: Some(
                spec.changed_at
                    .map_or(job.created_at, |at| at.max(job.created_at)),
            ),
            disabled: spec.disabled,
            when: spec.when()?,
            session: spec.session,
            idle_only: false,
            active_hours: None,
            model: None,
            prompt: JobPrompt::Inline(spec.prompt),
            ask_to: None,
            dm_excerpt: None,
        })
    }

    /// How the job is named to the model and in logs: `` `check-in` `` for a config job, `#3`
    /// for a runtime job.
    pub fn label(&self) -> String {
        match &self.key {
            JobKey::Config(id) => format!("`{id}`"),
            JobKey::Runtime(id) => format!("#{id}"),
        }
    }

    /// Whether the job fires once and is then deleted (a runtime job with a time).
    pub fn is_one_shot(&self) -> bool {
        matches!(self.when, When::At(_))
    }
}

/// The conversation a runtime job was scheduled in (the turn's that called the `schedule` tool):
/// an `isolated` run's reply goes there, and a `dm` run is a turn in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobConversation {
    /// The channel instance.
    pub channel: String,
    /// The conversation on it.
    pub id: ConversationId,
}

impl JobConversation {
    /// The session key of this conversation with `agent`.
    pub fn key(&self, agent: &AgentId) -> SessionKey {
        SessionKey {
            agent: agent.clone(),
            channel: self.channel.clone(),
            conversation: self.id.clone(),
        }
    }
}

/// A runtime job's definition, the `spec` column of `jobs`: written by the `schedule` tool,
/// read by the scheduler. Exactly one of `cron` and `at` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    /// A five-field cron pattern, read in the creator's time zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    /// The one time it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Timestamp>,
    /// The prompt.
    pub prompt: String,
    /// Which session it runs in.
    #[serde(default)]
    pub session: JobSession,
    /// The conversation it was scheduled in; `None` for a job scheduled on the web jobs page,
    /// which delivers to the user's default identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<JobConversation>,
    /// Switched off: the job keeps its row but doesn't run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// When the job was last edited or switched back on: the scheduler doesn't make up the times
    /// before it, as it does for times missed while Doozers was stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_at: Option<Timestamp>,
}

impl RuntimeSpec {
    /// When it fires.
    ///
    /// # Errors
    ///
    /// Neither or both of `cron` and `at`, or an invalid pattern.
    pub fn when(&self) -> Result<When, String> {
        match (&self.cron, self.at) {
            (Some(pattern), None) => parse_cron(pattern).map(|cron| When::Cron(Box::new(cron))),
            (None, Some(at)) => Ok(When::At(at)),
            _ => Err("a job needs exactly one of `cron` and `at`".to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use doozers_store::RuntimeJobId;
    use serde_json::json;

    use super::*;

    fn runtime(spec: serde_json::Value) -> RuntimeJob {
        RuntimeJob {
            id: RuntimeJobId::new(7),
            agent: AgentId::new("jeeves").unwrap(),
            creator: UserId::new("owner").unwrap(),
            spec,
            created_at: "2026-10-22T16:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn runtime_specs_parse_strictly() {
        let job = JobDef::from_runtime(&runtime(json!({
            "cron": "0 9 * * 1-5",
            "prompt": "Stand-up notes?",
            "session": "dm",
        })))
        .unwrap();
        assert_eq!(job.key, JobKey::Runtime(RuntimeJobId::new(7)));
        assert_eq!(job.label(), "#7");
        assert_eq!(job.creator, UserId::new("owner").ok());
        assert_eq!(job.session, JobSession::Dm);
        assert_eq!(job.prompt, JobPrompt::Inline("Stand-up notes?".into()));
        assert_eq!(job.conversation, None);
        assert!(!job.is_one_shot());

        let at = JobDef::from_runtime(&runtime(json!({
            "at": "2026-10-22T17:00:00Z",
            "prompt": "Tea.",
        })))
        .unwrap();
        assert!(at.is_one_shot());
        assert_eq!(at.session, JobSession::Isolated);

        for bad in [
            json!({"prompt": "p"}),
            json!({"cron": "0 9 * * *", "at": "2026-10-22T17:00:00Z", "prompt": "p"}),
            json!({"cron": "0 9 * *", "prompt": "p"}),
            json!({"cron": "0 9 * * *", "prompt": "p", "extra": 1}),
            json!({"cron": "0 9 * * *"}),
        ] {
            assert!(
                JobDef::from_runtime(&runtime(bad.clone())).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn specs_round_trip_without_unset_keys() {
        let spec = RuntimeSpec {
            cron: None,
            at: Some("2026-10-22T17:00:00Z".parse().unwrap()),
            prompt: "Tea.".into(),
            session: JobSession::Isolated,
            conversation: None,
            disabled: false,
            changed_at: None,
        };
        let value = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            value,
            json!({"at": "2026-10-22T17:00:00Z", "prompt": "Tea.", "session": "isolated"})
        );
        assert_eq!(serde_json::from_value::<RuntimeSpec>(value).unwrap(), spec);
    }

    #[test]
    fn a_runtime_job_keeps_the_conversation_it_was_scheduled_in() {
        let job = JobDef::from_runtime(&runtime(json!({
            "at": "2026-10-22T17:00:00Z",
            "prompt": "Tea.",
            "conversation": {"channel": "discord", "id": "1234"},
        })))
        .unwrap();
        let conversation = job.conversation.unwrap();
        assert_eq!(
            conversation.key(&job.agent),
            SessionKey {
                agent: job.agent.clone(),
                channel: "discord".into(),
                conversation: ConversationId::new("1234").unwrap(),
            }
        );
    }

    #[test]
    fn a_change_moves_the_time_missed_runs_are_made_up_from() {
        let job = JobDef::from_runtime(&runtime(json!({
            "cron": "0 9 * * *",
            "prompt": "p",
            "disabled": true,
            "changed_at": "2026-10-23T10:00:00Z",
        })))
        .unwrap();
        assert!(job.disabled);
        assert_eq!(job.since, "2026-10-23T10:00:00Z".parse().ok());

        let created =
            JobDef::from_runtime(&runtime(json!({"cron": "0 9 * * *", "prompt": "p"}))).unwrap();
        assert!(!created.disabled);
        assert_eq!(created.since, "2026-10-22T16:00:00Z".parse().ok());
    }
}
