//! Two users, logged in through real sessions, against the pages of the other's data. Users are
//! made through the `Users` API: the imported owner (an admin), a second admin `root`, and a
//! member `mia`. Every request here carries only a session cookie, as a browser's does, so the
//! role comes from the stored users.
//!
//! Each test names what the other user tries and what must be left as it was.

use doozers_store::{ConversationAccess, InboxState, NewInboxEvent};

use super::admin::{session_of, stored_users};
use super::chat_actions::Chats;
use super::*;

/// What a user's browser sends.
struct Browser {
    token: String,
}

impl Browser {
    async fn log_in(env: &Env, user: &str) -> Self {
        Self {
            token: session_of(env, user).await,
        }
    }

    /// `method path` on `router`, with the session cookie and this login's CSRF token in the
    /// header and, for a post, the form (`fields` after the CSRF field).
    async fn send(
        &self,
        router: axum::Router,
        method: Method,
        path: &str,
        fields: &str,
    ) -> Response {
        let csrf = auth::cookie_csrf(&self.token);
        let cookie = session(&self.token);
        let form = format!("csrf={csrf}&{fields}");
        call(
            router,
            method.clone(),
            path,
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
            (method == Method::POST).then_some(form.as_str()),
        )
        .await
    }
}

fn mia_user() -> UserId {
    UserId::new("mia").unwrap()
}

/// Stores a chat of `user` in `chat` with one user message `text`.
async fn chat_of(env: &Env, user: &UserId, chat: &ConversationId, text: &str) {
    let (session, _) = env
        .store
        .open_session(
            SessionKey {
                agent: AgentId::new("jeeves").unwrap(),
                channel: INSTANCE.into(),
                conversation: chat.clone(),
            },
            SessionKind::Direct,
            Some(user.clone()),
            Timestamp::now(),
        )
        .await
        .unwrap();
    env.store
        .append_messages(
            session.id,
            vec![stored(Role::User, vec![super::text(text)])],
        )
        .await
        .unwrap();
}

fn chat_n(n: u8) -> ConversationId {
    ConversationId::new(format!("{n:02x}").repeat(16)).unwrap()
}

/// The status of every request, and a check that none of the bodies has `secret`.
async fn assert_all_not_found(
    t: &Chats,
    who: &Browser,
    secret: &str,
    requests: &[(Method, String, &str)],
) {
    for (method, path, fields) in requests {
        let response = who.send(t.router(None), method.clone(), path, fields).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        let html = body_text(response).await;
        assert!(!html.contains(secret), "{method} {path}: {html}");
    }
}

#[tokio::test]
async fn another_users_chat_is_not_found_on_every_chat_route() {
    let t = Chats::new().await;
    let env = &t.env;
    stored_users(env).await;
    let owner_browser = Browser::log_in(env, "owner").await;
    let mia = Browser::log_in(env, "mia").await;
    let theirs = chat_n(0x11);
    chat_of(env, &identity::owner(), &theirs, "the owner secret plan").await;
    // The owner's chat has a prompt waiting for an answer and is archived apart from the list.
    env.channel
        .send_approval(&theirs, "4821", "Run `rm -rf /`?")
        .unwrap();
    let archived = chat_n(0x22);
    chat_of(
        env,
        &identity::owner(),
        &archived,
        "the owner archived secret",
    )
    .await;
    env.store
        .archive_conversation(INSTANCE, &archived, &identity::owner(), Timestamp::now())
        .await
        .unwrap();

    // The owner reads their chat.
    let response = owner_browser
        .send(t.router(None), Method::GET, &format!("/chats/{theirs}"), "")
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("the owner secret plan"), "{page}");
    assert!(page.contains("4821"), "{page}");

    // Mia names the owner's chat on every route that takes a chat id.
    let mut requests = Vec::new();
    for chat in [&theirs, &archived] {
        requests.extend([
            (Method::GET, format!("/chats/{chat}"), ""),
            (Method::GET, format!("/chats/{chat}/events"), ""),
            (Method::GET, format!("/chats/{chat}/events?after=0"), ""),
            (
                Method::POST,
                format!("/chats/{chat}/messages"),
                "text=hello",
            ),
            (
                Method::POST,
                format!("/chats/{chat}/approvals"),
                "code=4821&answer=yes",
            ),
            (
                Method::POST,
                format!("/chats/{chat}/approvals"),
                "code=4821&answer=yes!",
            ),
            (Method::POST, format!("/chats/{chat}/archive"), ""),
            (Method::POST, format!("/chats/{chat}/unarchive"), ""),
            (Method::POST, format!("/chats/{chat}/delete"), ""),
        ]);
    }
    assert_all_not_found(&t, &mia, "secret", &requests).await;

    // Nothing was posted, answered, archived, unarchived, or deleted, and the prompt's buttons
    // are still on the owner's page.
    assert!(env.pending_texts().await.is_empty());
    assert_eq!(
        env.store
            .conversation_archived_at(INSTANCE, &theirs)
            .await
            .unwrap(),
        None
    );
    assert!(
        env.store
            .conversation_archived_at(INSTANCE, &archived)
            .await
            .unwrap()
            .is_some()
    );
    for chat in [&theirs, &archived] {
        let rows = env
            .store
            .conversation_transcript(INSTANCE, chat, &identity::owner(), 10)
            .await
            .unwrap();
        assert_eq!(rows.messages.len(), 1, "{chat}");
    }
    let page = body_text(
        owner_browser
            .send(t.router(None), Method::GET, &format!("/chats/{theirs}"), "")
            .await,
    )
    .await;
    assert!(!page.contains("Sent: yes"), "{page}");

    // Mia's lists have neither chat.
    for path in ["/", "/chats/archived"] {
        let html = body_text(mia.send(t.router(None), Method::GET, path, "").await).await;
        assert!(!html.contains("secret"), "{path}: {html}");
        assert!(!html.contains(&theirs.to_string()), "{path}: {html}");
        assert!(!html.contains(&archived.to_string()), "{path}: {html}");
    }
}

#[tokio::test]
async fn a_chat_one_user_has_begun_is_not_found_for_another_before_the_core_takes_it() {
    let t = Chats::new().await;
    let env = &t.env;
    stored_users(env).await;
    let owner_browser = Browser::log_in(env, "owner").await;
    let mia = Browser::log_in(env, "mia").await;
    let fresh = chat_n(0x33);

    // The owner's first message is waiting for the core, so the chat has no session yet.
    let response = owner_browser
        .send(
            t.router(None),
            Method::POST,
            &format!("/chats/{fresh}/messages"),
            "text=my+first+message",
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        env.store
            .conversation_access(INSTANCE, &fresh, &identity::owner())
            .await
            .unwrap(),
        ConversationAccess::Unstarted
    );

    let requests = [
        (Method::GET, format!("/chats/{fresh}"), ""),
        (Method::GET, format!("/chats/{fresh}/events"), ""),
        (Method::POST, format!("/chats/{fresh}/messages"), "text=hi"),
        (
            Method::POST,
            format!("/chats/{fresh}/approvals"),
            "code=1&answer=no",
        ),
        (Method::POST, format!("/chats/{fresh}/delete"), ""),
    ];
    assert_all_not_found(&t, &mia, "my first message", &requests).await;
    assert_eq!(env.pending_texts().await, ["my first message"]);

    // The owner goes on using it.
    let response = owner_browser
        .send(t.router(None), Method::GET, &format!("/chats/{fresh}"), "")
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response).await.contains("my first message"));
}

#[tokio::test]
async fn each_user_has_their_own_chats_and_the_same_id_never_joins_two() {
    let t = Chats::new().await;
    let env = &t.env;
    stored_users(env).await;
    let owner_browser = Browser::log_in(env, "owner").await;
    let mia = Browser::log_in(env, "mia").await;
    let hers = chat_n(0x44);
    let his = chat_n(0x55);
    chat_of(env, &mia_user(), &hers, "mia family recipe").await;
    chat_of(env, &identity::owner(), &his, "the owner's tax return").await;

    // Each sees only their own chat in the list and can open it, post, archive, and unarchive.
    let list = body_text(mia.send(t.router(None), Method::GET, "/", "").await).await;
    assert!(list.contains("mia family recipe"), "{list}");
    assert!(!list.contains("tax return"), "{list}");
    let list = body_text(
        owner_browser
            .send(t.router(None), Method::GET, "/", "")
            .await,
    )
    .await;
    assert!(list.contains("tax return"), "{list}");
    assert!(!list.contains("recipe"), "{list}");

    let response = mia
        .send(
            t.router(None),
            Method::POST,
            &format!("/chats/{hers}/messages"),
            "text=more+salt",
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let events = env.pending().await;
    let ChannelEvent::Message { message, .. } = &events[1] else {
        panic!("{events:?}");
    };
    assert_eq!(message.sender.as_str(), "mia");
    assert_eq!(message.conversation.id, hers);

    for action in ["archive", "unarchive"] {
        let response = mia
            .send(
                t.router(None),
                Method::POST,
                &format!("/chats/{hers}/{action}"),
                "",
            )
            .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{action}");
    }

    // An inbound row the owner has waiting in their chat isn't in anyone else's transcript.
    let (open, _) = env
        .store
        .open_session(
            SessionKey {
                agent: AgentId::new("jeeves").unwrap(),
                channel: INSTANCE.into(),
                conversation: his.clone(),
            },
            SessionKind::Direct,
            Some(identity::owner()),
            Timestamp::now(),
        )
        .await
        .unwrap();
    env.store
        .inbox_insert(NewInboxEvent {
            instance: INSTANCE.into(),
            event_id: EventId::new("waiting-1").unwrap(),
            session: Some(open.id),
            user: Some(identity::owner()),
            payload: serde_json::json!({"type": "message", "text": "waiting for a turn"}),
            state: InboxState::Queued,
            received_at: Timestamp::now(),
        })
        .await
        .unwrap();
    let transcript = env
        .store
        .conversation_transcript(INSTANCE, &his, &mia_user(), 10)
        .await
        .unwrap();
    assert!(transcript.messages.is_empty());
    assert!(transcript.waiting.is_empty());
}

#[tokio::test]
async fn only_the_chats_user_can_answer_its_approval_prompt() {
    let t = Chats::new().await;
    let env = &t.env;
    stored_users(env).await;
    let owner_browser = Browser::log_in(env, "owner").await;
    let root = Browser::log_in(env, "root").await;
    let mia = Browser::log_in(env, "mia").await;
    let chat = chat_n(0x66);
    chat_of(env, &identity::owner(), &chat, "deploy it").await;
    env.channel
        .send_approval(&chat, "9d2", "Run `deploy`?")
        .unwrap();

    // No other user answers it, an admin included (an admin's role is no part of the rule).
    let path = format!("/chats/{chat}/approvals");
    for who in [&mia, &root] {
        for answer in ["yes", "yes!", "no"] {
            let response = who
                .send(
                    t.router(None),
                    Method::POST,
                    &path,
                    &format!("code=9d2&answer={answer}"),
                )
                .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{answer}");
        }
    }
    assert!(
        env.pending_texts().await.is_empty(),
        "nothing was sent to the core"
    );
    let page = body_text(
        owner_browser
            .send(t.router(None), Method::GET, &format!("/chats/{chat}"), "")
            .await,
    )
    .await;
    assert!(
        page.contains(r#"value="yes""#),
        "the prompt is still open: {page}"
    );

    // The chat's user answers it, as the core will read: `yes 9d2` from their own identity.
    let response = owner_browser
        .send(t.router(None), Method::POST, &path, "code=9d2&answer=yes")
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let events = env.pending().await;
    let [_, ChannelEvent::Message { message, .. }] = &events[..] else {
        panic!("{events:?}");
    };
    assert_eq!(message.text, "yes 9d2");
    assert_eq!(message.sender.as_str(), "owner");
}

#[tokio::test]
async fn a_deleted_chat_leaves_nothing_for_the_next_user_of_its_id_to_replay() {
    let t = Chats::new().await;
    let env = &t.env;
    stored_users(env).await;
    let owner_browser = Browser::log_in(env, "owner").await;
    let mia = Browser::log_in(env, "mia").await;
    let chat = chat_n(0x88);
    chat_of(env, &identity::owner(), &chat, "the deleted secret").await;
    env.channel
        .send_approval(&chat, "5150", "Run `the deleted secret`?")
        .unwrap();

    let response = owner_browser
        .send(
            t.router(None),
            Method::POST,
            &format!("/chats/{chat}/delete"),
            "",
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // The id is free again, but the events of the chat that had it are gone with its hub.
    let path = format!("/chats/{chat}/events?after={}", env.channel.hubs.cursor(0));
    let response = mia.send(t.router(None), Method::GET, &path, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    // Told to reload, as for any page from before a hub was dropped, and nothing more.
    let chunk = tokio::time::timeout(Duration::from_millis(200), body.next())
        .await
        .expect("the stream starts with the reload notice")
        .unwrap()
        .unwrap();
    let chunk = String::from_utf8(chunk.to_vec()).unwrap();
    assert!(chunk.contains("Reload the page"), "{chunk}");
    assert!(
        !chunk.contains("deleted secret") && !chunk.contains("5150"),
        "{chunk}"
    );
    let more = tokio::time::timeout(Duration::from_millis(200), body.next()).await;
    assert!(more.is_err(), "nothing is replayed: {more:?}");
    let page = body_text(
        mia.send(t.router(None), Method::GET, &format!("/chats/{chat}"), "")
            .await,
    )
    .await;
    assert!(!page.contains("deleted secret"), "{page}");
}
