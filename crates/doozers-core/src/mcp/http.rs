//! Remote MCP servers over streamable HTTP.

use std::time::Duration;

use doozers_types::{Error, Result};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::auth::{AuthClient, AuthorizationManager};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use url::Url;

use super::convert::Origin;
use crate::config::Secret;

/// A remote MCP server: a streamable HTTP endpoint (PLAN section 7.10). The deprecated HTTP+SSE
/// transport isn't supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpServer {
    /// The MCP endpoint, an `http` or `https` URL.
    pub url: Url,
    /// Sent as `Authorization: Bearer <token>` on every request (`auth = { bearer = ... }`), and
    /// scrubbed from error messages.
    pub bearer: Option<Secret>,
    /// Limit on establishing a connection, TLS handshake included.
    pub connect_timeout: Duration,
}

impl HttpServer {
    /// A server at `url`, without credentials, with a 10 second connect timeout.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            bearer: None,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// The secrets to scrub from this server's messages.
    pub(crate) fn secrets(&self) -> Vec<Secret> {
        self.bearer.iter().cloned().collect()
    }

    /// The `rmcp` transport for this server: a client from
    /// [`tls_client_builder`](crate::net::tls_client_builder) (bundled roots only, no redirects,
    /// so the token can't be forwarded to another host) with the connect timeout. There is no
    /// read timeout: the server's event stream may stay quiet between notifications.
    pub(crate) fn transport(
        &self,
        origin: &Origin,
    ) -> Result<StreamableHttpClientTransport<reqwest::Client>> {
        let client = self.client(origin)?;
        let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str());
        if let Some(bearer) = &self.bearer {
            // `reqwest` sends it with `bearer_auth`, which marks the header sensitive.
            config = config.auth_header(bearer.expose());
        }
        Ok(StreamableHttpClientTransport::with_client(client, config))
    }

    /// The `rmcp` transport for this server with a user's OAuth sign-in instead of `bearer`: the
    /// client of [`transport`](Self::transport), with `auth` adding the user's access token to
    /// every request. `auth` reads the token from its credential store each time, refreshing it
    /// when it is about to expire or the server rejects it.
    pub(crate) fn oauth_transport(
        &self,
        origin: &Origin,
        auth: AuthorizationManager,
    ) -> Result<StreamableHttpClientTransport<AuthClient<reqwest::Client>>> {
        let client = self.client(origin)?;
        let config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str());
        Ok(StreamableHttpClientTransport::with_client(
            AuthClient::new(client, auth),
            config,
        ))
    }

    fn client(&self, origin: &Origin) -> Result<reqwest::Client> {
        if !matches!(self.url.scheme(), "http" | "https") {
            return Err(Error::InvalidRequest(origin.message(format_args!(
                "the url must be http or https, not {}",
                self.url.scheme()
            ))));
        }
        crate::net::tls_client_builder()?
            .connect_timeout(self.connect_timeout)
            .build()
            .map_err(Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin {
            instance: "remote".to_owned(),
            secrets: Vec::new(),
        }
    }

    #[test]
    fn the_token_is_redacted() {
        let mut server = HttpServer::new("https://mcp.example.com/mcp".parse().unwrap());
        server.bearer = Some(Secret::new("s3cret-token"));
        let debug = format!("{server:?}");
        assert!(!debug.contains("s3cret-token"), "{debug}");
        assert_eq!(server.secrets(), [Secret::new("s3cret-token")]);
    }

    #[tokio::test]
    async fn only_http_urls_are_accepted() {
        for url in ["ftp://example.com/mcp", "file:///tmp/mcp"] {
            let server = HttpServer::new(url.parse().unwrap());
            let error = server.transport(&origin()).err().unwrap();
            assert!(
                matches!(error, Error::InvalidRequest(_)),
                "{url}: {error:?}"
            );
        }
        let server = HttpServer::new("https://example.com/mcp".parse().unwrap());
        assert!(server.transport(&origin()).is_ok());
    }
}
