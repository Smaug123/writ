//! The VM-HTTP route table: one classification of a guest request, consumed by
//! every stage of the dispatch.
//!
//! Three functions used to switch on the same target string independently —
//! auth-scheme selection, body-limit selection, and the routing if/else — and a
//! fourth bespoke branch decided which auth *denials* were audited. A new
//! capability had to touch all four, and nothing checked they agreed. Here the
//! request is classified **once**, into a route that answers all four questions.
//!
//! The invariant this buys, and the reason the `Plain` set is closed:
//!
//! > Every route is [`Brokered`](VmHttpRoute::Brokered) — reaching its effect's
//! > IO only through the `broker_effect` driver, which owns its
//! > `(request, outcome)` audit pair — or [`Plain`](VmHttpRoute::Plain), a named,
//! > reviewed variant that provably performs no brokered effect. Never neither,
//! > and never both.
//!
//! [`PlainRoute`] is deliberately a closed enum rather than an open extension
//! point: an open one would let a future *effectful* endpoint be registered as
//! plain and run IO outside `broker_effect` while a totality test still passed —
//! which is the original discipline gap, reintroduced.
//!
//! This is a discriminated union interpreted by a `match`, not the
//! `Box<dyn ErasedEffect>` the plan sketched. The registry entry is a
//! *description* of a route, and the codebase's rule is data descriptions over
//! behavioural abstractions: the variants are inspectable, the dispatcher's match
//! is exhaustive, and adding a capability is a compile error until every site
//! handles it. (The trait/driver split still applies where the plan intended it —
//! to the heterogeneous *execution*, behind `BrokeredEffect`.)

use crate::agent_run::AgentRunId;
use crate::secret::SecretStore;

use super::agent_runs::{parse_agent_run_config_target, parse_agent_run_outcome_target};
use super::flake_provision::is_flake_provision_target;
use super::git_clone::is_git_clone_target;
use super::git_push::is_git_push_target;
use super::nix_cache::is_nix_cache_target;
use super::nix_cache::record_nix_cache_local_response;
use super::proxy_common::record_proxy_local_response;
use super::proxy_common::{ProxyBackend, proxy_target_path};
use super::{ClaudeBackend, OpenAiBackend};
use super::{
    MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES, MAX_VM_HTTP_BODY_BYTES, VmHttpAuthError,
    VmHttpAuthScheme, VmHttpDispatch, VmHttpRequest, VmHttpResponse, VmHttpServices, VmHttpSession,
    vm_http_auth_error_reason,
};
use crate::audit::{NixCacheAuditDecision, ProxyAuditDecision};

/// Declare a route enum together with the name of every variant, so the two
/// cannot drift: a variant is unnameable without appearing in `ALL_NAMES`, which
/// is what the coverage tests enumerate. `name` is used only by tests and
/// diagnostics; it never enters SQL or a response.
macro_rules! route_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $enum_name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident $(($payload:ty))? ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $enum_name {
            $( $(#[$variant_meta])* $variant $(($payload))? ),*
        }

        // Test-support: the coverage oracles enumerate `ALL_NAMES` and label
        // failures with `name`. Neither is production code, so both are gated
        // rather than carried (and `dead_code`-exempt) in the shipped binary.
        #[cfg(test)]
        impl $enum_name {
            /// Every variant's name, generated from the same list as the enum
            /// itself — so a route cannot be added without the coverage tests
            /// noticing it is undriven.
            pub(super) const ALL_NAMES: &'static [&'static str] = &[$(stringify!($variant)),*];

            /// This route's variant name.
            pub(super) fn name(&self) -> &'static str {
                match self {
                    $( Self::$variant { .. } => stringify!($variant) ),*
                }
            }
        }
    };
}

/// How a guest request is handled, resolved once from its target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum VmHttpRoute {
    /// Records a `(request, outcome)` audit pair through the `broker_effect`
    /// driver. Its effect's IO is unreachable except through that driver.
    Brokered(BrokeredRoute),
    /// Explicitly non-audited, and a *closed* set: each variant states why it
    /// records nothing.
    Plain(PlainRoute),
}

route_enum! {
    /// An audited effect route. Each variant's handler does one thing: build the
    /// effect and hand it to `broker_effect`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum BrokeredRoute {
        /// `/v1/messages`, `/v1/messages/count_tokens`, `/v1/models/*`.
        ClaudeProxy,
        /// `/v1/responses`, `/v1/responses/{id}/cancel`. (Its models routes are
        /// shadowed by the Claude proxy — see the route-table tests.)
        OpenAiProxy,
        /// `/v1/nix/cache/*`, `/v1/nix/prewarm/*`. Authority-free, so its pair is
        /// written in one commit (`record_effect_coalesced`) rather than two.
        NixCache,
        /// `POST /v1/git/push` — stages a bundle for review.
        GitPush,
        /// `POST /v1/nix/flake/provision`.
        FlakeProvision,
        /// `POST /v1/agent-runs/{id}/outcome`. Outcome-only: it resumes the
        /// `agent_run` row minted when the run was launched.
        AgentRunOutcome(AgentRunId),
    }
}

route_enum! {
    /// A route that records no audit pair. Adding one is a deliberate, reviewed
    /// act — hence the closed enum and the per-variant justification.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) enum PlainRoute {
        /// `GET /v1/session`: reports the session's own id. Grants nothing,
        /// reaches nothing, has no `(request, outcome)` pair to record.
        Session,
        /// `GET /v1/agent-runs/{id}/config`: hands the guest the prompt and model
        /// for its own run, from an in-memory map, exactly once. It confers no
        /// host authority and performs no effect; the run's audit rows are
        /// written at launch and at outcome upload.
        AgentRunConfig(AgentRunId),
        /// `POST /v1/git/clone`: its audit *is* the host capability mint
        /// (`request` + one of `grant_log` / `mint_failure` / neither-on-deny), a
        /// decision-dependent three-way rather than an `EffectAuditTable` pair.
        /// It cannot supply a `(request, outcome)` table, so it is plain until
        /// the host-mint follow-up teaches the guard the grant-flow shape (see
        /// the plan's §7). It is *not* unaudited — it is audited elsewhere.
        GitClone,
        /// A model-proxy path from before the vendor namespaces — `/v1/messages`,
        /// `/v1/responses`, `/v1/models*`. Answered `410 Gone` naming the
        /// remedy, because a guest asking for these is running an image built
        /// before the split and would otherwise see an indistinguishable `404`.
        /// Records nothing: no effect was attempted. Deleted once stale guest
        /// images can no longer be in play (see
        /// `docs/plans/2026-07-25-proxy-vendor-namespaces.md`, Stage 2).
        LegacyProxyPath,
        /// No route matched: answered `404`/`405` without touching any service.
        Unmatched,
    }
}

/// Whether a route demands [`writ_vm_git::VM_HTTP_CONTRACT_HEADER`].
///
/// The broker cannot demand it of everything: most guest traffic is not ours.
/// Claude Code, codex and `nix` will never send a writ header, so requiring one
/// universally would break both model proxies and the binary cache. What it
/// *can* do is refuse a stale guest on the routes `writ-vm` itself originates —
/// which is where every damaging pre-effect action lives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContractCheck {
    /// Originated by `writ-vm`: refuse unless the declared version matches.
    Required,
    /// Exempt, and why it must be.
    Exempt(ContractExemption),
}

/// Why a route is exempt. A DU rather than a comment because the exemption set
/// is the part of this that can silently widen, and each variant is answerable
/// in review on its own terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContractExemption {
    /// The handshake itself. Gating `GET /v1/session` would make a mismatch
    /// *undiagnosable*: it is the endpoint a guest reads the broker's version
    /// out of, `writ-vm session` is exempted guest-side as the during-mismatch
    /// diagnostic for the same reason, and the readiness probes hand-roll it
    /// over a raw socket.
    Handshake,
    /// A third-party client — Claude Code, codex, `nix` — which has never heard
    /// of writ and will not send its headers.
    ThirdPartyClient,
    /// Nothing is reached and no effect is attempted, so the answer does not
    /// depend on the contract: `LegacyProxyPath`'s `410` names the rebuild and
    /// `Unmatched`'s `404` says there is no such endpoint, both of which tell a
    /// stale guest more than a version refusal would.
    NoEffect,
}

impl ContractCheck {
    /// A stable label for the contract fingerprint. Not `Debug`: which routes
    /// demand the header is part of the guest-facing contract, but how the enum
    /// is spelled is not. Test-only, like `identity`, since the fingerprint is
    /// the only thing that reads it.
    #[cfg(test)]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Exempt(ContractExemption::Handshake) => "exempt:handshake",
            Self::Exempt(ContractExemption::ThirdPartyClient) => "exempt:third-party",
            Self::Exempt(ContractExemption::NoEffect) => "exempt:no-effect",
        }
    }
}

impl VmHttpRoute {
    /// A stable name for the handler a target reaches, for the contract
    /// fingerprint. Deliberately not `Debug`: the guest-visible contract is
    /// *which handler serves this target*, so renaming a variant or changing an
    /// id type's formatting must not read as a contract change.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &'static str {
        match self {
            Self::Brokered(route) => route.name(),
            Self::Plain(route) => route.name(),
        }
    }

    /// Classify a request. Total, and a pure function of the target — the same
    /// key the three switch sites this replaces all used, so the classification
    /// cannot disagree with itself across the stages of one request.
    ///
    /// Deliberately *not* keyed on the method: each route applies its own method
    /// rule (the nix cache answers `405` for a write, git-push `404` for a
    /// non-POST), and folding those into resolution would change which status a
    /// wrong-method request gets.
    pub(crate) fn resolve(request: &VmHttpRequest) -> Self {
        let target = request.target.as_str();
        // Order mirrors the dispatcher's original if-chain. The prefixes are
        // disjoint, but preserving the order keeps that an observation rather
        // than a dependency.
        if is_nix_cache_target(target) {
            return Self::Brokered(BrokeredRoute::NixCache);
        }
        if ClaudeBackend::is_proxy_target(target) {
            return Self::Brokered(BrokeredRoute::ClaudeProxy);
        }
        if OpenAiBackend::is_proxy_target(target) {
            return Self::Brokered(BrokeredRoute::OpenAiProxy);
        }
        if is_git_clone_target(target) {
            return Self::Plain(PlainRoute::GitClone);
        }
        if is_git_push_target(target) {
            return Self::Brokered(BrokeredRoute::GitPush);
        }
        if is_flake_provision_target(target) {
            return Self::Brokered(BrokeredRoute::FlakeProvision);
        }
        if let Some(run_id) = parse_agent_run_config_target(target) {
            return Self::Plain(PlainRoute::AgentRunConfig(run_id));
        }
        if let Some(run_id) = parse_agent_run_outcome_target(target) {
            return Self::Brokered(BrokeredRoute::AgentRunOutcome(run_id));
        }
        if is_legacy_proxy_path(target) {
            return Self::Plain(PlainRoute::LegacyProxyPath);
        }
        if target == SESSION_PATH {
            return Self::Plain(PlainRoute::Session);
        }
        Self::Plain(PlainRoute::Unmatched)
    }

    /// Whether this route requires the guest to declare its contract version.
    ///
    /// The exhaustive `match` is the point: a new capability cannot be added
    /// without stating which side of the line it is on, and — because every
    /// exemption carries its reason — without saying why if it is exempt.
    pub(crate) fn contract_check(&self) -> ContractCheck {
        use ContractExemption::{Handshake, NoEffect, ThirdPartyClient};
        match self {
            Self::Brokered(
                BrokeredRoute::GitPush
                | BrokeredRoute::FlakeProvision
                | BrokeredRoute::AgentRunOutcome(_),
            )
            | Self::Plain(PlainRoute::GitClone | PlainRoute::AgentRunConfig(_)) => {
                ContractCheck::Required
            }
            Self::Brokered(BrokeredRoute::ClaudeProxy) => ContractCheck::Exempt(ThirdPartyClient),
            Self::Brokered(BrokeredRoute::OpenAiProxy) => ContractCheck::Exempt(ThirdPartyClient),
            Self::Brokered(BrokeredRoute::NixCache) => ContractCheck::Exempt(ThirdPartyClient),
            Self::Plain(PlainRoute::Session) => ContractCheck::Exempt(Handshake),
            Self::Plain(PlainRoute::LegacyProxyPath | PlainRoute::Unmatched) => {
                ContractCheck::Exempt(NoEffect)
            }
        }
    }

    /// Which credential this route expects. The nix cache speaks the binary-cache
    /// protocol, which `nix` authenticates with HTTP Basic; everything else takes
    /// the session bearer token.
    pub(super) fn auth_scheme(&self) -> VmHttpAuthScheme {
        match self {
            Self::Brokered(BrokeredRoute::NixCache) => VmHttpAuthScheme::Basic,
            _ => VmHttpAuthScheme::Bearer,
        }
    }

    /// The maximum request-body bytes this route will consume, or `None` if it
    /// does not read a body — in which case any declared body is left in the
    /// connection rather than buffered.
    ///
    /// `None` for a route whose service is not configured, so a disabled
    /// capability never buffers a body before answering `404`.
    pub(super) fn body_limit<S: SecretStore + Send + Sync + 'static>(
        &self,
        request: &VmHttpRequest,
        services: &VmHttpServices<S>,
    ) -> Option<usize> {
        match self {
            // The cache serves reads; it never reads a request body.
            Self::Brokered(BrokeredRoute::NixCache) => None,
            Self::Brokered(BrokeredRoute::ClaudeProxy) => services
                .claude_proxy
                .as_ref()
                .map(|service| service.config.max_request_bytes()),
            Self::Brokered(BrokeredRoute::OpenAiProxy) => services
                .openai_proxy
                .as_ref()
                .map(|service| service.config.max_request_bytes()),
            Self::Brokered(BrokeredRoute::GitPush) => (request.method == "POST")
                .then(|| {
                    services
                        .git_push
                        .as_ref()
                        .map(|service| service.body_limits().max_body_bytes())
                })
                .flatten(),
            Self::Brokered(BrokeredRoute::FlakeProvision) => (request.method == "POST"
                && services.flake_provision.is_some())
            .then_some(MAX_VM_HTTP_BODY_BYTES),
            Self::Brokered(BrokeredRoute::AgentRunOutcome(_)) => (request.method == "POST"
                && services.agent_runs.is_some())
            .then_some(MAX_VM_HTTP_AGENT_RUN_OUTCOME_BODY_BYTES),
            Self::Plain(PlainRoute::GitClone) => (request.method == "POST"
                && services.git_clone.is_some())
            .then_some(MAX_VM_HTTP_BODY_BYTES),
            // Neither reads a body.
            Self::Plain(PlainRoute::Session | PlainRoute::AgentRunConfig(_)) => None,
            // Answered without reading the body it declares: the guest is
            // misconfigured, and buffering a model request to discard it would
            // be pure waste.
            Self::Plain(PlainRoute::LegacyProxyPath) => None,
            // Nothing to read a body for.
            Self::Plain(PlainRoute::Unmatched) => None,
        }
    }
}

impl VmHttpRoute {
    /// Answer an authentication failure, recording it against this route's own
    /// audit table where that table can express a denial.
    ///
    /// This is why the route is resolved *before* authentication: an auth denial
    /// on an audited route is itself an audited event (a guest hammering the
    /// model proxies with a bad token is exactly what a reviewer wants to see),
    /// and it is now the matched route that decides how to record it, rather
    /// than a bespoke if/else beside the dispatcher that had to re-classify the
    /// target a fourth time.
    ///
    /// Routes whose tables have no denial shape — and every [`PlainRoute`] —
    /// return the response unrecorded, exactly as before.
    pub(super) fn record_auth_denial<S: SecretStore + Send + Sync + 'static>(
        &self,
        services: &VmHttpServices<S>,
        session: &VmHttpSession,
        request: &VmHttpRequest,
        err: VmHttpAuthError,
        response: VmHttpResponse,
    ) -> VmHttpDispatch {
        let reason = || vm_http_auth_error_reason(err).to_string();
        match self {
            Self::Brokered(BrokeredRoute::NixCache) => record_nix_cache_local_response(
                services.nix_cache.as_ref(),
                session,
                request,
                NixCacheAuditDecision::Deny { reason: reason() },
                response,
                None,
            )
            .into(),
            Self::Brokered(BrokeredRoute::ClaudeProxy) => {
                match (
                    ClaudeBackend::classify_proxy_target(&request.target),
                    services.claude_proxy.as_ref(),
                ) {
                    (Some(route), Some(service)) => {
                        record_proxy_local_response::<ClaudeBackend, _>(
                            service,
                            session,
                            request,
                            route,
                            ProxyAuditDecision::Deny { reason: reason() },
                            response,
                            None,
                        )
                        .into()
                    }
                    // The proxy is not configured (or, defensively, the target
                    // no longer classifies): there is no table to record into.
                    _ => response.into(),
                }
            }
            Self::Brokered(BrokeredRoute::OpenAiProxy) => {
                match (
                    OpenAiBackend::classify_proxy_target(&request.target),
                    services.openai_proxy.as_ref(),
                ) {
                    (Some(route), Some(service)) => {
                        record_proxy_local_response::<OpenAiBackend, _>(
                            service,
                            session,
                            request,
                            route,
                            ProxyAuditDecision::Deny { reason: reason() },
                            response,
                            None,
                        )
                        .into()
                    }
                    _ => response.into(),
                }
            }
            // Git-push, flake provisioning, and agent-run outcomes have no
            // denial variant in their outcome tables — an unauthenticated
            // request never reached the effect, and their rows describe effects,
            // not attempts to authenticate.
            Self::Brokered(
                BrokeredRoute::GitPush
                | BrokeredRoute::FlakeProvision
                | BrokeredRoute::AgentRunOutcome(_),
            ) => response.into(),
            Self::Plain(_) => response.into(),
        }
    }
}

/// The `GET /v1/session` path, matched by [`VmHttpRoute::resolve`] and served by
/// the session endpoint.
pub(super) const SESSION_PATH: &str = "/v1/session";

/// Whether `target` is a model-proxy path from before the vendor namespaces.
///
/// These roots are disjoint from writ's own `/v1/*` API (`session`, `git`,
/// `nix`, `agent-runs`), which is unaffected by the split — after it, `/v1/*`
/// belongs solely to writ.
fn is_legacy_proxy_path(target: &str) -> bool {
    let path = proxy_target_path(target);
    ["/v1/messages", "/v1/responses", "/v1/models"]
        .iter()
        .any(|root| path == *root || path.starts_with(&format!("{root}/")))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use proptest::prelude::*;

    use super::*;

    fn request(method: &str, target: &str) -> VmHttpRequest {
        VmHttpRequest::new(
            method,
            target,
            None,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345)),
        )
    }

    /// Every endpoint in the architecture doc's endpoint map, with the route it
    /// must resolve to. This is the totality oracle: a route that stops
    /// resolving — or starts resolving to the wrong kind, which would change its
    /// auth scheme, its body limit, *and* whether it is audited — fails here.
    pub(crate) const ENDPOINT_MAP: &[(&str, &str, &str)] = &[
        ("GET", "/v1/session", "Session"),
        ("GET", "/v1/nix/cache/nix-cache-info", "NixCache"),
        ("GET", "/v1/nix/cache/abc.narinfo", "NixCache"),
        ("GET", "/v1/nix/prewarm/nix-cache-info", "NixCache"),
        ("POST", "/anthropic/v1/messages", "ClaudeProxy"),
        ("POST", "/anthropic/v1/messages/count_tokens", "ClaudeProxy"),
        ("GET", "/anthropic/v1/models", "ClaudeProxy"),
        ("GET", "/anthropic/v1/models/claude-opus-4-1", "ClaudeProxy"),
        ("POST", "/openai/v1/responses", "OpenAiProxy"),
        (
            "POST",
            "/openai/v1/responses/resp_123/cancel",
            "OpenAiProxy",
        ),
        ("GET", "/openai/v1/models", "OpenAiProxy"),
        ("GET", "/openai/v1/models/gpt-5", "OpenAiProxy"),
        ("POST", "/v1/messages", "LegacyProxyPath"),
        ("POST", "/v1/git/clone", "GitClone"),
        ("POST", "/v1/git/push", "GitPush"),
        ("POST", "/v1/nix/flake/provision", "FlakeProvision"),
        (
            "GET",
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/config",
            "AgentRunConfig",
        ),
        (
            "POST",
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/outcome",
            "AgentRunOutcome",
        ),
    ];

    #[test]
    fn every_documented_endpoint_resolves_to_its_route() {
        for (method, target, expected) in ENDPOINT_MAP {
            let route = VmHttpRoute::resolve(&request(method, target));
            let name = match &route {
                VmHttpRoute::Brokered(brokered) => brokered.name(),
                VmHttpRoute::Plain(plain) => plain.name(),
            };
            assert_eq!(&name, expected, "{method} {target} resolved to {route:?}");
        }
    }

    /// The endpoint map must exercise *every* route, brokered and plain alike.
    /// Because `ALL_NAMES` is generated from the enum definition, a new route
    /// fails here until it is documented above — and, for a brokered one, until
    /// the audit-pair drive test in `vm_http::tests` covers it too.
    #[test]
    fn the_endpoint_map_covers_every_route() {
        let documented: BTreeSet<&str> = ENDPOINT_MAP.iter().map(|(_, _, name)| *name).collect();
        let mut expected: BTreeSet<&str> = BrokeredRoute::ALL_NAMES.iter().copied().collect();
        expected.extend(PlainRoute::ALL_NAMES.iter().copied());
        // `Unmatched` is the fallthrough, covered by its own test below rather
        // than by a documented endpoint.
        expected.remove("Unmatched");

        assert_eq!(
            documented, expected,
            "the endpoint map and the route table have drifted",
        );
    }

    /// Each vendor's models routes reach *its own* backend. Before the
    /// namespaces this was impossible: `/v1/models` is a real endpoint of both
    /// APIs, so the backend classified first (Claude) swallowed the other's —
    /// answering `404` from the wrong proxy and recording the attempt against
    /// the wrong vendor's audit table.
    #[test]
    fn each_vendors_models_routes_reach_its_own_backend() {
        for target in [
            "/anthropic/v1/models",
            "/anthropic/v1/models/claude-opus-4-1",
        ] {
            assert_eq!(
                VmHttpRoute::resolve(&request("GET", target)),
                VmHttpRoute::Brokered(BrokeredRoute::ClaudeProxy),
                "{target}",
            );
        }
        for target in ["/openai/v1/models", "/openai/v1/models/gpt-5"] {
            assert_eq!(
                VmHttpRoute::resolve(&request("GET", target)),
                VmHttpRoute::Brokered(BrokeredRoute::OpenAiProxy),
                "{target}",
            );
        }
    }

    /// Every pre-split model-proxy path is retired together, so a stale guest
    /// gets one consistent answer rather than a mix of `410` and `404`.
    #[test]
    fn the_pre_split_proxy_paths_are_all_retired() {
        for target in [
            "/v1/messages",
            "/v1/messages/count_tokens",
            "/v1/responses",
            "/v1/responses/resp_123/cancel",
            "/v1/models",
            "/v1/models/gpt-5",
            // Query strings must not smuggle a legacy path past the check.
            "/v1/models?limit=1",
        ] {
            assert_eq!(
                VmHttpRoute::resolve(&request("GET", target)),
                VmHttpRoute::Plain(PlainRoute::LegacyProxyPath),
                "{target}",
            );
        }
    }

    /// After the split, `/v1/*` belongs solely to writ's own API. Nothing there
    /// may resolve to a vendor proxy — the collision that started this was two
    /// vendor APIs sharing one namespace, and writ's own API shares it too.
    #[test]
    fn writs_own_v1_api_is_never_a_proxy_route() {
        for target in [
            "/v1/session",
            "/v1/git/clone",
            "/v1/git/push",
            "/v1/nix/cache/nix-cache-info",
            "/v1/nix/flake/provision",
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/config",
            "/v1/agent-runs/00000000-0000-0000-0000-000000000001/outcome",
        ] {
            let route = VmHttpRoute::resolve(&request("GET", target));
            assert!(
                !matches!(
                    route,
                    VmHttpRoute::Brokered(BrokeredRoute::ClaudeProxy | BrokeredRoute::OpenAiProxy)
                ),
                "{target} resolved to a model proxy: {route:?}",
            );
        }
    }

    /// **What the guest declares on, and what the broker demands, must agree.**
    ///
    /// Not an equality — `GET /v1/session` is writ-vm-originated and exempt,
    /// because gating the endpoint a guest reads the broker's version out of
    /// makes a skew undiagnosable. Two implications instead, and each catches a
    /// different way this can go wrong.
    #[test]
    fn the_header_is_demanded_of_exactly_the_routes_the_guest_declares_on() {
        // (1) Nothing `writ-vm` originates may be exempted for a reason that
        // belongs to somebody else's client. `Handshake` is the one exemption a
        // route of ours may claim, and it is named, not inferred.
        let mut originated: BTreeSet<&str> = BTreeSet::new();
        for (method, target) in writ_vm_git::WRIT_VM_ORIGINATED_TARGETS {
            let route = VmHttpRoute::resolve(&request(method, target));
            assert!(
                matches!(
                    route.contract_check(),
                    ContractCheck::Required | ContractCheck::Exempt(ContractExemption::Handshake)
                ),
                "`{method} {target}` is originated by writ-vm but is {:?}: a route of ours may \
                 only be exempt as the handshake",
                route.contract_check(),
            );
            originated.insert(route.identity());
        }

        // (2) The broker may not demand a declaration on a route the guest never
        // declares on — that would refuse legitimate traffic, in the VM, where
        // it is least diagnosable.
        for (method, target, _) in ENDPOINT_MAP {
            let route = VmHttpRoute::resolve(&request(method, target));
            if route.contract_check() == ContractCheck::Required {
                assert!(
                    originated.contains(route.identity()),
                    "`{method} {target}` demands the contract header, but `{}` is not in \
                     WRIT_VM_ORIGINATED_TARGETS — no guest sends one there",
                    route.identity(),
                );
            }
        }
    }

    /// Path segments the two vendor APIs and writ's own API are built from, so
    /// the generator searches the space where a collision would actually live
    /// rather than random noise.
    fn target_strategy() -> impl Strategy<Value = String> {
        let segment = prop::sample::select(vec![
            "v1",
            "anthropic",
            "openai",
            "messages",
            "count_tokens",
            "responses",
            "models",
            "cancel",
            "session",
            "git",
            "clone",
            "push",
            "nix",
            "cache",
            "flake",
            "provision",
            "agent-runs",
            "gpt-5",
            "claude-opus-4-1",
            "resp_123",
        ]);
        prop::collection::vec(segment, 1..5).prop_map(|segments| format!("/{}", segments.join("/")))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// **At most one** proxy backend may claim any target.
        ///
        /// This is the invariant whose absence produced the bug this test was
        /// written for: `/v1/models` is a real endpoint of *both* vendor APIs, so
        /// whichever backend was classified first silently swallowed the other's
        /// models routes — answering `404` from the wrong proxy and recording the
        /// attempt against the wrong vendor's audit table. No ordering fixes
        /// that; the ambiguity is in the address space, so each vendor gets its
        /// own namespace and this property holds by construction.
        ///
        /// Run against the pre-split code it shrinks to exactly `/v1/models`.
        #[test]
        fn no_target_is_claimed_by_both_proxy_backends(target in target_strategy()) {
            let claude = ClaudeBackend::classify_proxy_target(&target).is_some();
            let openai = OpenAiBackend::classify_proxy_target(&target).is_some();
            prop_assert!(
                !(claude && openai),
                "`{target}` is claimed by both proxy backends: whichever is classified first \
                 shadows the other, and the loser's requests are answered and audited by the \
                 wrong vendor's proxy",
            );
        }
    }

    /// **The guest's configuration and the host's routing must agree.**
    ///
    /// `writ-vm` points each agent at a base URL; its SDK then appends its own
    /// well-known suffixes. This takes the very base URLs the guest is
    /// configured with, appends what each vendor's SDK appends, and asserts the
    /// *host's* route table sends the result to that vendor's proxy.
    ///
    /// Nothing checked this before, which is how the namespaces drifted in the
    /// first place: the guest asked for `/v1/models` and the host answered from
    /// whichever proxy it classified first.
    #[test]
    fn the_guests_configured_base_urls_route_to_their_own_vendor() {
        const BROKER: &str = "http://192.168.252.1:49152/";

        // Claude Code appends `/v1/...` to ANTHROPIC_BASE_URL.
        let anthropic = writ_vm_git::anthropic_proxy_base_url(BROKER);
        for suffix in ["/v1/messages", "/v1/messages/count_tokens", "/v1/models"] {
            let target = path_of(&format!("{anthropic}{suffix}"));
            assert_eq!(
                VmHttpRoute::resolve(&request("POST", &target)),
                VmHttpRoute::Brokered(BrokeredRoute::ClaudeProxy),
                "{target}",
            );
        }

        // codex's base_url already carries `/v1`; it appends bare names.
        let openai = writ_vm_git::openai_proxy_base_url(BROKER);
        for suffix in ["/responses", "/models"] {
            let target = path_of(&format!("{openai}{suffix}"));
            assert_eq!(
                VmHttpRoute::resolve(&request("POST", &target)),
                VmHttpRoute::Brokered(BrokeredRoute::OpenAiProxy),
                "{target}",
            );
        }
    }

    /// The path a guest actually puts on the wire for an absolute URL.
    fn path_of(url: &str) -> String {
        reqwest::Url::parse(url)
            .expect("the guest's base URL joins to a valid URL")
            .path()
            .to_string()
    }

    #[test]
    fn an_unknown_target_is_unmatched() {
        assert_eq!(
            VmHttpRoute::resolve(&request("GET", "/v1/not-a-route")),
            VmHttpRoute::Plain(PlainRoute::Unmatched),
        );
        // A near-miss on an audited prefix must not be absorbed by it.
        assert_eq!(
            VmHttpRoute::resolve(&request("POST", "/v1/git/pushed")),
            VmHttpRoute::Plain(PlainRoute::Unmatched),
        );
    }

    /// Resolution is a pure function of the target, so the classification cannot
    /// differ between the auth, body-limit, and dispatch stages of one request.
    #[test]
    fn resolution_does_not_depend_on_the_method() {
        for (_, target, _) in ENDPOINT_MAP {
            let get = VmHttpRoute::resolve(&request("GET", target));
            for method in ["POST", "PUT", "DELETE", "HEAD"] {
                assert_eq!(
                    VmHttpRoute::resolve(&request(method, target)),
                    get,
                    "{method} {target}",
                );
            }
        }
    }

    /// Only the nix cache speaks Basic; everything else takes the session bearer
    /// token. Pinned because the scheme now comes from the resolved route rather
    /// than a separate target test.
    #[test]
    fn only_the_nix_cache_uses_basic_auth() {
        for (method, target, _) in ENDPOINT_MAP {
            let route = VmHttpRoute::resolve(&request(method, target));
            let expected = if matches!(route, VmHttpRoute::Brokered(BrokeredRoute::NixCache)) {
                VmHttpAuthScheme::Basic
            } else {
                VmHttpAuthScheme::Bearer
            };
            assert_eq!(route.auth_scheme(), expected, "{target}");
        }
    }
}
