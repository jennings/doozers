//! Users and their channel identities (PLAN sections 1.1 and 3.2): [`User`], and [`UserList`], the
//! snapshot of every user the [router](crate::router::Router) and the web login read for each
//! message. Design: `Docs/technical/identity-and-routing.md`.
//!
//! The list is replaced as a whole whenever a user changes (the [`RouteList`](crate::routes::RouteList)
//! pattern), so a message is resolved against one consistent set of users, and resolving it never
//! touches the database.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use doozers_store::{Role, UserState, Verification, canonical_identity};
use doozers_types::{InboundMessage, NativeId, Timestamp, UserId};
use jiff::tz::TimeZone;

use crate::config::{Identity, OwnerConfig};
use crate::identity;

/// A user: a person who talks to the agents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct User {
    /// The user's id: opaque and never changed. The id of the user `[owner]` described is
    /// [`identity::OWNER`].
    pub id: UserId,
    /// The username.
    pub username: String,
    /// The name people see.
    pub display_name: String,
    /// What the user may do.
    pub role: Role,
    /// Whether the user can use Doozers now.
    pub state: UserState,
    /// The user's time zone, for message time prefixes and job schedules. `None`: the agent's
    /// `timezone`, else the system time zone.
    pub timezone: Option<TimeZone>,
    /// The identity jobs and proactive messages go to; one of `identities`. `None` if the user
    /// has no identity a channel can reach.
    pub default_identity: Option<Identity>,
    /// The identities that act as this user, oldest first.
    pub identities: Vec<UserIdentity>,
}

/// A channel identity of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UserIdentity {
    /// `<namespace>:<native id>`.
    pub identity: Identity,
    /// When it was established as the user's.
    pub verified_at: Timestamp,
    /// How it was established.
    pub verification: Verification,
}

impl User {
    /// Whether the user can use Doozers now.
    pub fn is_active(&self) -> bool {
        self.state == UserState::Active
    }
}

/// The directory of users one [`UserList`] snapshot holds.
#[derive(Debug, Default)]
pub struct UserDirectory {
    users: Vec<User>,
    by_id: HashMap<UserId, usize>,
    /// The index of each identity's user, by [`identity_key`].
    by_identity: HashMap<String, usize>,
}

impl UserDirectory {
    fn new(users: Vec<User>) -> Self {
        let mut by_id = HashMap::with_capacity(users.len());
        let mut by_identity = HashMap::new();
        for (index, user) in users.iter().enumerate() {
            by_id.insert(user.id.clone(), index);
            for identity in &user.identities {
                by_identity.insert(identity_key(identity.identity.as_str()), index);
            }
        }
        Self {
            users,
            by_id,
            by_identity,
        }
    }

    /// Every user, oldest first.
    pub fn users(&self) -> &[User] {
        &self.users
    }

    /// The user `id`, if there is one.
    pub fn user(&self, id: &UserId) -> Option<&User> {
        self.by_id.get(id).map(|&index| &self.users[index])
    }

    /// The user who has the identity `<namespace>:<id>`.
    ///
    /// The comparison is exact (case-sensitive) except in the `email` namespace (first segment
    /// `email`), where the domain, after the last `@`, is compared ASCII case-insensitively; the
    /// local part stays case-sensitive, as RFC 5321 allows mail servers to treat it so.
    pub fn resolve(&self, namespace: &str, id: &NativeId) -> Option<&User> {
        let key = identity_key(&format!("{namespace}:{id}"));
        self.by_identity.get(&key).map(|&index| &self.users[index])
    }

    /// The user the message's sender is: the one who has the sender's identity or, if none does,
    /// the first alias that is anyone's.
    pub fn resolve_sender(&self, namespace: &str, message: &InboundMessage) -> Option<&User> {
        message
            .sender_ids()
            .find_map(|id| self.resolve(namespace, id))
    }
}

/// The key identities are compared by: the joined identity in its
/// [canonical form](doozers_store::canonical_identity), which the store keeps them in too.
fn identity_key(identity: &str) -> String {
    canonical_identity(identity)
}

/// The users the router and the web login read. Cheap to clone; clones share the list.
///
/// [`get`](Self::get) returns a snapshot, so a message is resolved against one set of users even if
/// they change meanwhile.
#[derive(Debug, Clone, Default)]
pub struct UserList {
    current: Arc<RwLock<Arc<UserDirectory>>>,
}

impl UserList {
    /// Starts with `users`.
    pub fn new(users: Vec<User>) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(UserDirectory::new(users)))),
        }
    }

    /// The users now.
    pub fn get(&self) -> Arc<UserDirectory> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Replaces the users; messages resolved after this returns use them.
    pub fn set(&self, users: Vec<User>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) =
            Arc::new(UserDirectory::new(users));
    }

    /// The time zone of user `id`, if the user exists and has set one.
    pub fn timezone(&self, id: &UserId) -> Option<TimeZone> {
        self.get().user(id)?.timezone.clone()
    }

    /// The list of the one user `[owner]` of `doozers.toml` describes.
    pub fn from_owner(owner: &OwnerConfig, now: Timestamp) -> Self {
        let identities = owner
            .identities
            .iter()
            .map(|identity| UserIdentity {
                identity: identity.clone(),
                verified_at: now,
                verification: Verification::Imported,
            })
            .collect();
        Self::new(vec![User {
            id: identity::owner(),
            username: identity::OWNER.to_owned(),
            display_name: "Owner".to_owned(),
            role: Role::Admin,
            state: UserState::Active,
            timezone: owner.timezone.clone(),
            default_identity: Some(owner.default.clone()),
            identities,
        }])
    }
}

#[cfg(test)]
impl User {
    /// An active member `id` with `identities` and no time zone.
    pub(crate) fn member(id: &str, identities: &[&str]) -> Self {
        Self {
            id: UserId::new(id).unwrap(),
            username: id.to_owned(),
            display_name: id.to_owned(),
            role: Role::Member,
            state: UserState::Active,
            timezone: None,
            default_identity: None,
            identities: identities
                .iter()
                .map(|identity| UserIdentity {
                    identity: Identity::new(*identity).unwrap(),
                    verified_at: Timestamp::UNIX_EPOCH,
                    verification: Verification::Imported,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
impl UserList {
    /// The owner with `identities`, the first of them the default, and `timezone` if set.
    pub(crate) fn owner(identities: &[&str], timezone: Option<&str>) -> Self {
        let identities: Vec<Identity> = identities
            .iter()
            .map(|identity| Identity::new(*identity).unwrap())
            .collect();
        Self::from_owner(
            &OwnerConfig {
                default: identities[0].clone(),
                identities,
                timezone: timezone.map(|name| TimeZone::get(name).unwrap()),
            },
            Timestamp::UNIX_EPOCH,
        )
    }
}

#[cfg(test)]
mod tests {
    use doozers_types::{ConversationId, ConversationKind, ConversationRef};

    use super::*;

    fn native(id: &str) -> NativeId {
        NativeId::new(id).unwrap()
    }

    fn resolves(list: &UserList, namespace: &str, id: &str) -> bool {
        list.get().resolve(namespace, &native(id)).is_some()
    }

    fn owner_ids(ids: &[&str]) -> UserList {
        UserList::owner(ids, None)
    }

    #[test]
    fn identities_match_exactly_across_the_joined_namespace() {
        let list = owner_ids(&["whatsapp:+15551234567", "irc:libera.chat:account:stephen"]);
        assert!(resolves(&list, "whatsapp", "+15551234567"));
        assert!(resolves(&list, "irc:libera.chat", "account:stephen"));
        // Not another number, another namespace, or another case.
        assert!(!resolves(&list, "whatsapp", "+15550000000"));
        assert!(!resolves(&list, "irc:other.net", "account:stephen"));
        assert!(!resolves(&list, "irc:libera.chat", "account:Stephen"));
        // A namespace may contain `:`, so only the whole joined string matters.
        assert!(!resolves(&list, "irc", "libera.chat"));
        assert!(!resolves(&list, "irc:libera.chat:account", "stephen-x"));
    }

    #[test]
    fn an_email_domain_matches_in_any_case_and_the_local_part_does_not() {
        let list = owner_ids(&["email:me@example.com", "email:Case@example.org"]);
        assert!(resolves(&list, "email", "me@example.com"));
        assert!(resolves(&list, "email", "me@Example.COM"));
        assert!(!resolves(&list, "email", "Me@example.com"));
        assert!(resolves(&list, "email", "Case@EXAMPLE.org"));
        assert!(!resolves(&list, "email", "case@example.org"));
        // The configured domain's case doesn't matter either.
        let list = owner_ids(&["email:me@Example.com"]);
        assert!(resolves(&list, "email", "me@example.com"));
        // Only the `email` namespace gets this.
        let list = owner_ids(&["other:me@example.com"]);
        assert!(!resolves(&list, "other", "me@EXAMPLE.com"));
        // A sub-namespace of `email` does too: the first segment names the namespace.
        let list = owner_ids(&["email:work:me@example.com"]);
        assert!(resolves(&list, "email:work", "me@EXAMPLE.com"));
    }

    #[test]
    fn matching() {
        let owner = owner_ids(&[
            "whatsapp:+15551234567",
            "irc:libera.chat:account:stephen",
            "email:Me@Example.com",
            "web:owner",
        ]);
        let yes = [
            ("whatsapp", "+15551234567"),
            ("irc:libera.chat", "account:stephen"),
            ("web", "owner"),
            ("email", "Me@Example.com"),
            ("email", "Me@example.COM"),
        ];
        for (namespace, id) in yes {
            assert!(resolves(&owner, namespace, id), "{namespace}:{id}");
        }
        let no = [
            // Another namespace or a near miss on the namespace boundary.
            ("whatsapp:x", "+15551234567"),
            ("whats", "app:+15551234567"),
            ("irc:oftc", "account:stephen"),
            ("irc:libera.chat", "account:Stephen"),
            ("irc:libera.chat", "account:stephe"),
            ("irc:libera.chat", "account:stephenx"),
            ("WEB", "owner"),
            ("web", "Owner"),
            // Email local parts stay case-sensitive.
            ("email", "me@example.com"),
            ("email", "Me@Example.org"),
            ("email", "Me"),
            // The domain rule is only for the email namespace.
            ("whatsapp", "+15551234567@S"),
        ];
        for (namespace, id) in no {
            assert!(!resolves(&owner, namespace, id), "{namespace}:{id}");
        }
    }

    #[test]
    fn email_without_at_sign_is_exact() {
        let owner = owner_ids(&["email:postmaster"]);
        assert!(resolves(&owner, "email", "postmaster"));
        assert!(!resolves(&owner, "email", "Postmaster"));
    }

    #[test]
    fn the_sender_wins_over_its_aliases_and_an_alias_resolves_when_the_sender_does_not() {
        let list = UserList::new(vec![
            user("a", &["whatsapp:+1"]),
            user("b", &["whatsapp:123@lid", "whatsapp:+2"]),
        ]);
        let mut message = message("+2");
        message.sender_aliases = vec![native("+1")];
        let directory = list.get();
        assert_eq!(
            directory.resolve_sender("whatsapp", &message).unwrap().id,
            UserId::new("b").unwrap()
        );
        message.sender = native("+9");
        assert_eq!(
            directory.resolve_sender("whatsapp", &message).unwrap().id,
            UserId::new("a").unwrap()
        );
        message.sender_aliases.clear();
        assert!(directory.resolve_sender("whatsapp", &message).is_none());
    }

    fn message(sender: &str) -> InboundMessage {
        InboundMessage {
            conversation: ConversationRef {
                id: ConversationId::new(sender).unwrap(),
                kind: ConversationKind::Direct,
                title: None,
            },
            sender: native(sender),
            sender_aliases: Vec::new(),
            sender_authenticated: true,
            sender_display_name: None,
            text: "hi".to_owned(),
            attachments: Vec::new(),
            message_id: None,
            reply_to: None,
            sent_at: None,
        }
    }

    fn user(id: &str, identities: &[&str]) -> User {
        User::member(id, identities)
    }

    #[test]
    fn a_replaced_list_applies_to_the_next_lookup_and_snapshots_stay_whole() {
        let list = owner_ids(&["web:owner"]);
        let clone = list.clone();
        let before = list.get();
        clone.set(vec![user("ann", &["web:ann"])]);
        assert!(resolves(&list, "web", "ann"));
        assert!(!resolves(&list, "web", "owner"));
        // A snapshot taken earlier still sees the users it was made with.
        assert!(before.resolve("web", &native("owner")).is_some());
        assert!(before.user(&UserId::new("ann").unwrap()).is_none());
        assert_eq!(
            list.timezone(&UserId::new("ann").unwrap()),
            None,
            "no time zone set"
        );
    }

    #[test]
    fn the_owner_list_has_the_owner_as_an_active_admin_with_its_time_zone() {
        let list = UserList::owner(&["web:owner"], Some("America/Los_Angeles"));
        let directory = list.get();
        let owner = directory.user(&identity::owner()).unwrap();
        assert_eq!(owner.role, Role::Admin);
        assert!(owner.is_active());
        assert_eq!(
            owner.default_identity.as_ref().map(Identity::as_str),
            Some("web:owner")
        );
        assert_eq!(
            list.timezone(&identity::owner()).unwrap().iana_name(),
            Some("America/Los_Angeles")
        );
    }
}
