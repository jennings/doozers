//! Which addresses OAuth requests for a remote toolset may reach.
//!
//! The URLs these requests go to (the protected-resource and authorization server metadata, the
//! token and registration endpoints) come from the MCP server, so a malicious or compromised
//! server could aim them at the network Giles runs in. Public addresses are always allowed. A
//! loopback or private address only when the MCP server's own URL names one: a loopback or
//! private IP literal, or `localhost`. What the MCP server's host name resolves to never widens
//! this, since whoever runs the server may control that too. Link-local (cloud instance metadata),
//! unspecified, broadcast, multicast, and reserved addresses are never allowed. The rule is the one
//! `rmcp` applies with its own HTTP client, which Giles doesn't use.
//!
//! Hosts of proxies set in the environment (`HTTPS_PROXY` and the rest) aren't filtered: a
//! proxied request resolves only the proxy, and the proxy resolves the target.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::{Host, Url};

const PROXY_VARIABLES: [&str; 6] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// What kind of network an address is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    Public,
    Loopback,
    Private,
    Blocked,
}

impl Class {
    pub(super) fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::of_v4(v4),
            IpAddr::V6(v6) => match embedded_v4(v6) {
                Some(v4) => Self::of_v4(v4),
                None => Self::of_v6(v6),
            },
        }
    }

    fn of_v4(addr: Ipv4Addr) -> Self {
        let [a, b, ..] = addr.octets();
        if addr.is_loopback() {
            Self::Loopback
        } else if addr.is_private() || (a == 100 && (64..=127).contains(&b)) {
            Self::Private
        } else if addr.is_link_local()
            || addr.is_unspecified()
            || addr.is_broadcast()
            || addr.is_multicast()
            || addr.is_documentation()
            || a == 0
            || a >= 240
            || (a == 198 && matches!(b, 18 | 19))
            || (a == 192 && b == 0 && addr.octets()[2] == 0)
        {
            Self::Blocked
        } else {
            Self::Public
        }
    }

    fn of_v6(addr: Ipv6Addr) -> Self {
        let segments = addr.segments();
        if addr.is_loopback() {
            Self::Loopback
        } else if (segments[0] & 0xfe00) == 0xfc00 {
            Self::Private
        } else if addr.is_unspecified()
            || addr.is_multicast()
            || (segments[0] & 0xffc0) == 0xfe80
            || segments[..2] == [0x2001, 0x0db8]
            || segments[..2] == [0x2001, 0]
            || segments[..3] == [0x64, 0xff9b, 1]
        {
            Self::Blocked
        } else {
            Self::Public
        }
    }
}

/// The IPv4 address an IPv6 address carries (mapped, NAT64, compatible, 6to4), if any.
fn embedded_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let [a, b, c, d, e, f, g, h] = addr.segments();
    let low = Ipv4Addr::from((u32::from(g) << 16) | u32::from(h));
    match [a, b, c, d, e, f] {
        [0, 0, 0, 0, 0, 0xffff] | [0x64, 0xff9b, 0, 0, 0, 0] => Some(low),
        [0, 0, 0, 0, 0, 0] if !addr.is_loopback() && !addr.is_unspecified() => Some(low),
        [0x2002, ..] => Some(Ipv4Addr::from((u32::from(b) << 16) | u32::from(c))),
        _ => None,
    }
}

/// The addresses OAuth requests for the MCP server at one URL may reach.
#[derive(Debug, Clone)]
pub(super) struct Policy {
    /// The classes beyond public that the server's URL allows.
    allowed: Vec<Class>,
    /// Proxy hosts, lower case, which aren't filtered.
    proxies: Arc<[String]>,
}

impl Policy {
    /// The policy for the MCP server at `server`, with the proxies of the process environment
    /// exempt.
    pub(super) fn for_server(server: &Url) -> Self {
        let proxies = PROXY_VARIABLES
            .iter()
            .filter_map(|variable| std::env::var(variable).ok())
            .filter_map(|proxy| {
                let proxy = if proxy.contains("://") {
                    proxy
                } else {
                    format!("http://{proxy}")
                };
                Url::parse(&proxy).ok()?.host_str().map(normalize)
            })
            .collect();
        Self::with_proxies(server, proxies)
    }

    fn with_proxies(server: &Url, proxies: Arc<[String]>) -> Self {
        let allowed = match server.host() {
            Some(Host::Ipv4(v4)) => vec![Class::of(IpAddr::V4(v4))],
            Some(Host::Ipv6(v6)) => vec![Class::of(IpAddr::V6(v6))],
            Some(Host::Domain(domain)) if is_localhost(domain) => vec![Class::Loopback],
            _ => Vec::new(),
        };
        Self { allowed, proxies }
    }

    fn allows(&self, addr: IpAddr) -> bool {
        match Class::of(addr) {
            Class::Public => true,
            class @ (Class::Loopback | Class::Private) => self.allowed.contains(&class),
            Class::Blocked => false,
        }
    }

    /// Whether a request to `url` may go out: an IP-literal host (which is connected to without
    /// resolving) must be allowed, and `localhost` counts as loopback. Other names are checked as
    /// they resolve ([`Resolver`]).
    pub(super) fn allows_url(&self, url: &Url) -> bool {
        match url.host() {
            Some(Host::Ipv4(v4)) => self.allows(IpAddr::V4(v4)),
            Some(Host::Ipv6(v6)) => self.allows(IpAddr::V6(v6)),
            Some(Host::Domain(domain)) if is_localhost(domain) => {
                self.allowed.contains(&Class::Loopback)
            }
            Some(Host::Domain(_)) => true,
            None => false,
        }
    }
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn is_localhost(domain: &str) -> bool {
    let domain = normalize(domain);
    domain == "localhost" || domain.ends_with(".localhost")
}

/// Resolves names with the system resolver and keeps only the addresses the policy allows.
pub(super) struct Resolver(pub(super) Policy);

impl Resolve for Resolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.0.clone();
        Box::pin(async move {
            let host = normalize(name.as_str());
            let resolved: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if policy.proxies.contains(&host) {
                return Ok(Box::new(resolved.into_iter()) as Addrs);
            }
            let allowed: Vec<SocketAddr> = resolved
                .into_iter()
                .filter(|addr| policy.allows(addr.ip()))
                .collect();
            if allowed.is_empty() {
                return Err(format!(
                    "`{host}` resolves only to addresses an OAuth request for this MCP server \
                     may not reach"
                )
                .into());
            }
            Ok(Box::new(allowed.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(server: &str) -> Policy {
        Policy::with_proxies(&server.parse().unwrap(), Arc::from(Vec::new()))
    }

    fn allows(policy: &Policy, url: &str) -> bool {
        policy.allows_url(&url.parse().unwrap())
    }

    #[test]
    fn a_public_server_reaches_only_public_addresses() {
        let public = policy("https://mcp.example.com/mcp");
        assert!(allows(&public, "https://auth.example.com/token"));
        assert!(allows(&public, "https://8.8.8.8/token"));
        for blocked in [
            "http://127.0.0.1/token",
            "http://localhost:8080/token",
            "http://api.localhost/token",
            "http://10.0.0.9/token",
            "http://192.168.1.1/token",
            "http://172.16.0.1/token",
            "http://100.64.0.1/token",
            "http://169.254.169.254/latest/meta-data",
            "http://0.0.0.0/token",
            "http://[::1]/token",
            "http://[fd00::1]/token",
            "http://[fe80::1]/token",
            "http://[::ffff:127.0.0.1]/token",
            "http://[::ffff:169.254.169.254]/token",
        ] {
            assert!(!allows(&public, blocked), "{blocked}");
        }
    }

    #[test]
    fn a_loopback_or_private_server_allows_its_own_class_and_never_link_local() {
        let loopback = policy("http://127.0.0.1:9000/mcp");
        assert!(allows(&loopback, "http://127.0.0.1:9001/token"));
        assert!(allows(&loopback, "http://localhost/token"));
        assert!(!allows(&loopback, "http://10.0.0.1/token"));
        assert!(allows(
            &policy("http://localhost:9000/mcp"),
            "http://[::1]/token"
        ));

        let private = policy("http://10.0.0.5/mcp");
        assert!(allows(&private, "http://10.1.2.3/token"));
        assert!(allows(&private, "http://192.168.0.1/token"));
        assert!(!allows(&private, "http://127.0.0.1/token"));
        for server in ["http://127.0.0.1/mcp", "http://10.0.0.5/mcp"] {
            assert!(
                !allows(&policy(server), "http://169.254.169.254/latest/meta-data"),
                "{server}"
            );
        }
    }

    #[tokio::test]
    async fn names_are_filtered_as_they_resolve() {
        let resolver = Resolver(policy("https://mcp.example.com/mcp"));
        let err = match resolver.resolve("localhost".parse().unwrap()).await {
            Ok(_) => panic!("localhost resolved for a public server"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("may not reach"), "{err}");
        let loopback = Resolver(policy("http://127.0.0.1/mcp"));
        assert!(loopback.resolve("localhost".parse().unwrap()).await.is_ok());
    }
}
