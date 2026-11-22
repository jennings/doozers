//! Step-up through the real handlers: a session that didn't come from an invite or recovery link
//! changes sign-in methods only after the user signed in again, and a session that was only
//! stolen can't. The password way is here; the passkey and identity provider ways are with the
//! tests that have their authenticator and provider (`passkeys.rs`, `oidc.rs`).

use std::time::Duration;

use axum::http::header::RETRY_AFTER;

use super::account::{Browser, Page};
use super::ssh_keys::url_encode;
use super::*;
use crate::channels::web::limits::USERNAME_ATTEMPTS;
use crate::channels::web::password::check_new;

pub(super) const GOOD: &str = "correct horse battery staple";
pub(super) const NEW: &str = "another long and unusual passphrase";

pub(super) fn minutes(minutes: u64) -> Duration {
    Duration::from_secs(minutes * 60)
}

impl Page {
    /// A browser of `user` whose session signed in with a password, like any of the 30-day logins
    /// a stolen cookie would be.
    pub(super) async fn password_login(&self, user: &str) -> Browser {
        let token = random_hex(32);
        let now = Timestamp::now();
        self.env
            .store
            .web_session_create(
                &token,
                UserId::new(user).unwrap(),
                SignInMethod::Password,
                now,
                now.checked_add(minutes(60)).unwrap(),
            )
            .await
            .unwrap();
        Browser::new(token)
    }

    /// A browser of `user` whose session signed in with `method` `age` ago.
    pub(super) async fn aged_login(
        &self,
        user: &str,
        method: SignInMethod,
        age: Duration,
    ) -> Browser {
        let token = random_hex(32);
        let now = Timestamp::now();
        self.env
            .store
            .web_session_create(
                &token,
                UserId::new(user).unwrap(),
                method,
                now.checked_sub(age).unwrap(),
                now.checked_add(minutes(600)).unwrap(),
            )
            .await
            .unwrap();
        Browser::new(token)
    }

    /// Gives `user` the password `password`, without the pages.
    pub(super) async fn give_password(&self, user: &str, password: &str) {
        let normalized = check_new(password, user).unwrap();
        let hash = self.env.app.inner.passwords.hash(normalized).await.unwrap();
        self.env
            .store
            .user_password_set(&UserId::new(user).unwrap(), &hash, Timestamp::now())
            .await
            .unwrap();
    }

    /// Pretends the user re-verified `ago` ago in `browser`'s session.
    pub(super) async fn reverified_ago(&self, browser: &Browser, ago: Duration) {
        let at = Timestamp::now().checked_sub(ago).unwrap();
        assert!(
            self.env
                .store
                .web_session_reverified(&browser.token, at)
                .await
                .unwrap()
        );
    }

    /// The re-verification time stored on the browser's session.
    pub(super) async fn reverified_at(&self, browser: &Browser) -> Option<Timestamp> {
        self.env
            .store
            .web_session(&browser.token, Timestamp::now())
            .await
            .unwrap()
            .unwrap()
            .reverified_at
    }

    /// `POST /setup/password` with a new password, the way the setup form does.
    pub(super) async fn set_new_password(&self, browser: &Browser) -> Answer {
        self.post(
            browser,
            "/setup/password",
            &[("password", NEW), ("confirm", NEW)],
        )
        .await
    }
}

use super::account::Answer;

/// Where a request that needs the user to sign in again first is sent for `next`.
pub(super) fn sign_in_again_for(next: &str) -> String {
    format!("/account/reverify?next={}", url_encode(next))
}

/// Asserts that `answer` sends the browser to sign in again before it goes on to `next`.
#[track_caller]
pub(super) fn assert_sign_in_again(answer: &Answer, next: &str) {
    assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.body);
    assert_eq!(
        answer.location.as_deref(),
        Some(sign_in_again_for(next).as_str()),
        "{next}"
    );
}

#[tokio::test]
async fn a_session_that_did_not_come_from_a_link_cannot_change_sign_in_methods() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let mia = UserId::new("mia").unwrap();
    let before = p.env.store.user_password(&mia).await.unwrap().unwrap();
    // What a stolen cookie is: a live session that signed in with a password a while ago.
    let stolen = p.password_login("mia").await;

    let page = p.get(&stolen, "/setup/password").await;
    assert_sign_in_again(&page, "/setup/password");
    let answer = p.set_new_password(&stolen).await;
    assert_sign_in_again(&answer, "/setup/password");
    assert_eq!(
        p.env.store.user_password(&mia).await.unwrap().unwrap(),
        before,
        "nothing changed"
    );
    let page = p.get(&stolen, "/setup/passkey").await;
    assert_sign_in_again(&page, "/setup/passkey");
    // The setup page lists every way to add, and each leads to signing in again.
    let setup = p.get(&stolen, "/setup").await;
    assert_eq!(setup.status, StatusCode::OK, "{}", setup.body);
    assert!(
        setup.body.contains(r#"href="/setup/password""#),
        "{}",
        setup.body
    );
    assert!(
        setup.body.contains(r#"href="/setup/passkey""#),
        "{}",
        setup.body
    );
    assert!(!setup.body.contains("Confirm it"), "{}", setup.body);

    // A recovery link's session still can, as before, and its pages lead back to the setup page.
    let recovery = p.login("mia").await;
    let page = p.get(&recovery, "/setup/password").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains(r#"<a href="/setup">Back to setup</a>"#),
        "{}",
        page.body
    );
    let answer = p.set_new_password(&recovery).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn signing_in_again_with_the_password_lets_that_session_and_no_other_change_methods() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let mia = UserId::new("mia").unwrap();
    let session = p.password_login("mia").await;
    let other = p.password_login("mia").await;

    // The page offers the methods the user has: a password, and nothing else.
    let page = p
        .get(&session, "/account/reverify?next=/setup/password")
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains("<h1>Sign in again to change your password</h1>"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("Continue with your password"),
        "{}",
        page.body
    );
    assert!(page.body.contains(r#"action="/account/reverify/password""#));
    assert!(page.body.contains(r#"name="next" value="/setup/password""#));
    assert!(!page.body.contains("passkey-reverify"), "{}", page.body);
    assert!(!page.body.contains("identity provider"), "{}", page.body);

    // A wrong password signs in nothing.
    let answer = p
        .post(
            &session,
            "/account/reverify/password",
            &[
                ("password", "not it, not at all"),
                ("next", "/setup/password"),
            ],
        )
        .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert!(
        answer.body.contains("That isn&#39;t your password."),
        "{}",
        answer.body
    );
    assert_eq!(p.reverified_at(&session).await, None);
    assert_sign_in_again(&p.set_new_password(&session).await, "/setup/password");

    // The right one is stored on the session, and leads on to the page the user was after.
    let answer = p
        .post(
            &session,
            "/account/reverify/password",
            &[("password", GOOD), ("next", "/setup/password")],
        )
        .await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.body);
    assert_eq!(answer.location.as_deref(), Some("/setup/password"));
    let at = p.reverified_at(&session).await.expect("stored");
    assert!(Timestamp::now().duration_since(at).as_secs() < 60);
    let page = p.get(&session, "/setup/password").await;
    assert_eq!(page.status, StatusCode::OK);
    // Its pages lead back to the account page it came from.
    assert!(
        page.body
            .contains(r#"<a href="/account">Back to your account</a>"#),
        "{}",
        page.body
    );
    assert_eq!(
        p.set_new_password(&session).await.status,
        StatusCode::SEE_OTHER
    );
    let changed = p.env.store.user_password(&mia).await.unwrap().unwrap();
    assert!(changed.changed_at >= at);

    // Another login of the same user didn't sign in again, so it still can't.
    assert_eq!(p.reverified_at(&other).await, None);
    assert_sign_in_again(&p.set_new_password(&other).await, "/setup/password");
    // And nobody else's session is changed by it.
    let root = p.password_login("root").await;
    assert_sign_in_again(&p.set_new_password(&root).await, "/setup/password");
}

#[tokio::test]
async fn where_signing_in_again_leads_is_only_ever_one_of_the_places_that_asked() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    let account = "/account?notice=reverified";
    let connect = format!("/setup/oidc/idp?csrf={}", url_encode(&session.csrf));
    for (next, to) in [
        ("https://evil.example/", account.to_owned()),
        ("//evil.example", account.to_owned()),
        ("/admin", account.to_owned()),
        ("/account/reverify", account.to_owned()),
        ("/setup/oidc/Bad%20Id", account.to_owned()),
        ("/setup/oidc/idp/extra", account.to_owned()),
        ("/setup/oidc/idp?csrf=x", account.to_owned()),
        ("/account/sign-in/remove?method=bogus", account.to_owned()),
        ("/account/sign-in/remove", account.to_owned()),
        (
            "/account/sign-in/remove?method=password&x=1",
            account.to_owned(),
        ),
        ("/account", account.to_owned()),
        ("/setup", "/setup".to_owned()),
        ("/setup/passkey", "/setup/passkey".to_owned()),
        (
            "/account/sign-in/remove?method=password",
            "/account/sign-in/remove?method=password".to_owned(),
        ),
        (
            "/account/sign-in/remove?method=passkey:7",
            "/account/sign-in/remove?method=passkey:7".to_owned(),
        ),
        (
            "/account/sign-in/remove?method=oidc:idp",
            "/account/sign-in/remove?method=oidc:idp".to_owned(),
        ),
    ] {
        let answer = p
            .post(
                &session,
                "/account/reverify/password",
                &[("password", GOOD), ("next", next)],
            )
            .await;
        assert_eq!(answer.location.as_deref(), Some(to.as_str()), "{next}");
    }
    // A connection ends at the provider, off this site, and the page's `form-action 'self'` would
    // stop a form submission whose redirects lead there. So the password form is answered with a
    // page that refreshes on to the start of the connection, which has the CSRF token the server
    // adds, and a link to it.
    let answer = p
        .post(
            &session,
            "/account/reverify/password",
            &[("password", GOOD), ("next", "/setup/oidc/idp")],
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.location, None);
    assert!(
        answer.body.contains(&format!(
            r#"<meta http-equiv="refresh" content="0; url={connect}">"#
        )),
        "{}",
        answer.body
    );
    assert!(
        answer
            .body
            .contains(&format!(r#"href="{connect}">Continue to idp"#)),
        "{}",
        answer.body
    );
    let page = p
        .get(&session, "/account/reverify?next=https://evil.example/")
        .await;
    assert!(
        page.body.contains(r#"name="next" value="/account""#),
        "{}",
        page.body
    );
    let answer = p.get(&session, "/account?notice=reverified").await;
    assert!(
        answer.body.contains("You signed in again."),
        "{}",
        answer.body
    );
    assert!(!answer.body.contains("onfirm"), "{}", answer.body);
}

#[tokio::test]
async fn signing_in_again_with_the_password_continues_to_the_removal_page() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    let remove = "/account/sign-in/remove?method=password";

    // Asking to remove the password sends the user to sign in again, for exactly that.
    let ask = p.get(&session, remove).await;
    assert_sign_in_again(&ask, remove);
    let page = p.get(&session, ask.location.as_deref().unwrap()).await;
    assert!(
        page.body
            .contains("<h1>Sign in again to remove your password</h1>"),
        "{}",
        page.body
    );

    // Signing in again goes straight on to the confirmation page, which now serves.
    let answer = p
        .post(
            &session,
            "/account/reverify/password",
            &[("password", GOOD), ("next", remove)],
        )
        .await;
    assert_eq!(answer.location.as_deref(), Some(remove));
    let ask = p.get(&session, remove).await;
    assert_eq!(ask.status, StatusCode::OK, "{}", ask.body);
    assert!(
        ask.body.contains("<h1>Remove your password?</h1>"),
        "{}",
        ask.body
    );
}

#[tokio::test]
async fn signing_in_again_lasts_ten_minutes() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    let second = Duration::from_secs(1);
    for (ago, status) in [
        (Duration::from_secs(0), StatusCode::OK),
        (minutes(9), StatusCode::OK),
        (minutes(10) - second, StatusCode::OK),
        (minutes(10), StatusCode::SEE_OTHER),
        (minutes(10) + second, StatusCode::SEE_OTHER),
        (minutes(11), StatusCode::SEE_OTHER),
    ] {
        p.reverified_ago(&session, ago).await;
        let answer = p.get(&session, "/setup/password").await;
        assert_eq!(answer.status, status, "{ago:?}");
        if status == StatusCode::SEE_OTHER {
            assert_sign_in_again(&answer, "/setup/password");
        }
    }
}

#[tokio::test]
async fn a_links_session_changes_methods_without_signing_in_again_only_for_thirty_minutes() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let second = Duration::from_secs(1);
    let aged = |method: SignInMethod, age: Duration| {
        let p = &p;
        async move {
            let token = random_hex(32);
            let now = Timestamp::now();
            p.env
                .store
                .web_session_create(
                    &token,
                    UserId::new("mia").unwrap(),
                    method,
                    now.checked_sub(age).unwrap(),
                    now.checked_add(minutes(600)).unwrap(),
                )
                .await
                .unwrap();
            Browser::new(token)
        }
    };
    for method in [SignInMethod::Invite, SignInMethod::Recovery] {
        for (age, status) in [
            (Duration::from_secs(0), StatusCode::OK),
            (minutes(29), StatusCode::OK),
            (minutes(30) - second, StatusCode::OK),
            (minutes(30), StatusCode::SEE_OTHER),
            (minutes(31), StatusCode::SEE_OTHER),
            (minutes(60 * 24 * 20), StatusCode::SEE_OTHER),
        ] {
            let session = aged(method, age).await;
            let answer = p.get(&session, "/setup/password").await;
            assert_eq!(answer.status, status, "{method:?} {age:?}");
            if status == StatusCode::SEE_OTHER {
                assert_sign_in_again(&answer, "/setup/password");
            }
        }
    }
    // An old one signs in again like any other session.
    let old = aged(SignInMethod::Recovery, minutes(45)).await;
    assert_sign_in_again(&p.get(&old, "/setup/password").await, "/setup/password");
    let answer = p
        .post(
            &old,
            "/account/reverify/password",
            &[("password", GOOD), ("next", "/setup")],
        )
        .await;
    assert_eq!(answer.location.as_deref(), Some("/setup"));
    let setup = p.get(&old, "/setup").await.body;
    assert!(setup.contains(r#"<a href="/setup/password">"#), "{setup}");
    assert_eq!(p.set_new_password(&old).await.status, StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn signing_in_again_needs_the_csrf_token_a_login_and_a_user_who_has_a_password() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    let answer = p
        .send(
            Some(&session),
            Method::POST,
            "/account/reverify/password",
            Some(&format!("password={}", url_encode(GOOD))),
        )
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    let answer = p
        .send(
            None,
            Method::POST,
            "/account/reverify/password",
            Some("csrf=x&password=y"),
        )
        .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    let answer = p.send(None, Method::GET, "/account/reverify", None).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(p.reverified_at(&session).await, None);

    // Someone with no password gets the same answer for any password, and is told what to do.
    let root = p.password_login("root").await;
    let page = p.get(&root, "/account/reverify").await;
    assert!(
        page.body.contains("You have no way to reauthenticate."),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("doozers admin login-link"),
        "{}",
        page.body
    );
    assert!(page.body.contains("30 minutes"), "{}", page.body);
    assert!(
        !page.body.contains("/account/reverify/password\""),
        "{}",
        page.body
    );
    let answer = p
        .post(&root, "/account/reverify/password", &[("password", GOOD)])
        .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(p.reverified_at(&root).await, None);
}

#[tokio::test]
async fn guessing_the_password_to_sign_in_again_counts_like_logging_in_with_it() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    // Failed logins of the username, from anywhere, use up the allowance...
    for _ in 0..USERNAME_ATTEMPTS {
        let form = format!("username=mia&password=wrong+wrong+wrong&nonce={NONCE}");
        let cookie = format!("{NONCE_COOKIE}={NONCE}");
        let response = call(
            p.router(),
            Method::POST,
            "/login/password",
            &[("cookie", &cookie)],
            Some(&form),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // ...so a stolen cookie can't guess for the password either, not even with the right one.
    let answer = p
        .post(
            &session,
            "/account/reverify/password",
            &[("password", GOOD)],
        )
        .await;
    assert_eq!(
        answer.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        answer.body
    );
    assert_eq!(p.reverified_at(&session).await, None);

    // And the other way: wrong guesses here use up what logging in has.
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let session = p.password_login("mia").await;
    for _ in 0..USERNAME_ATTEMPTS {
        let answer = p
            .post(
                &session,
                "/account/reverify/password",
                &[("password", "wrong wrong wrong")],
            )
            .await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    }
    let response = {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/account/reverify/password")
            .header("cookie", format!("{SESSION_COOKIE}={}", session.token))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(format!(
                "csrf={}&password={}",
                session.csrf,
                url_encode(GOOD)
            )))
            .unwrap();
        request.headers_mut();
        p.router().oneshot(request).await.unwrap()
    };
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(RETRY_AFTER));
    assert_eq!(p.reverified_at(&session).await, None);
}

#[tokio::test]
async fn a_proxy_login_has_no_session_to_sign_in_again_and_is_told_what_to_do() {
    let p = Page::new().await;
    p.give_password("mia", GOOD).await;
    let proxy = WebUser {
        user: UserId::new("mia").unwrap(),
        role: doozers_store::Role::Member,
        display_name: "MIA".into(),
        sender: NativeId::new("mia").unwrap(),
        csrf: "csrf-of-proxy".into(),
        login: auth::Login::Proxy,
    };
    let send = |method: Method, path: &'static str, form: Option<String>| {
        let (p, proxy) = (&p, proxy.clone());
        async move {
            call(
                p.router().layer(Extension(proxy)),
                method,
                path,
                &[],
                form.as_deref(),
            )
            .await
        }
    };
    // The page that adds or changes sends it to the page that says what to do instead...
    let response = send(Method::GET, "/setup/password", None).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[LOCATION],
        sign_in_again_for("/setup/password")
    );
    // ...which offers none of the user's ways, however many they have.
    let response = send(
        Method::GET,
        "/account/reverify?next=%2Fsetup%2Fpassword",
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = body_text(response).await;
    assert!(
        html.contains("<h1>Sign in again to change your password</h1>"),
        "{html}"
    );
    assert!(html.contains("proxy in front of Doozers"), "{html}");
    assert!(html.contains("doozers admin login-link"), "{html}");
    assert!(html.contains("recovery link"), "{html}");
    assert!(html.contains("30 minutes"), "{html}");
    assert!(!html.contains("/account/reverify/password"), "{html}");
    assert!(!html.contains("Continue with"), "{html}");
    // And nothing it posts signs in again.
    let response = send(
        Method::POST,
        "/account/reverify/password",
        Some(format!("csrf=csrf-of-proxy&password={}", url_encode(GOOD))),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let html = body_text(response).await;
    assert!(html.contains("proxy in front of Doozers"), "{html}");
}
