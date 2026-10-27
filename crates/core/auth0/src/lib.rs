//! Auth0 is the only source of platform authority. Mongo remains the profile store.
use async_trait::async_trait;
use futures::lock::Mutex as AsyncMutex;
use jsonwebtoken::{
    decode, decode_header, errors::ErrorKind, jwk::JwkSet, Algorithm, DecodingKey, Validation,
};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const JWKS_TTL: Duration = Duration::from_secs(600);
const JWKS_REFRESH_MIN: Duration = Duration::from_secs(30);
/// Last-good keys outlive the TTL only this long while Auth0 is unreachable, so a key
/// revoked during an outage stops granting privilege within a bounded time.
const JWKS_MAX_STALE: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_JWKS_KEYS: usize = 100;
const PRIVILEGED_PERMISSION: &str = "revolt:privileged";

/// Public tenant settings; secrets and Management API access are not needed.
pub struct Config {
    pub issuer: String,
    pub audience: String,
    pub claims_ns: String,
    pub jwks_uri: String,
}

impl Config {
    /// Matches microservices' Auth0 settings, without production fallbacks.
    pub fn from_env() -> Result<Self, &'static str> {
        let issuer = std::env::var("AUTH0_ISSUER")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("AUTH0_DOMAIN").ok().map(|s| {
                    let domain = s
                        .trim()
                        .trim_start_matches("https://")
                        .trim_end_matches('/');
                    format!("https://{domain}")
                })
            })
            .ok_or("Missing AUTH0_ISSUER or AUTH0_DOMAIN")?;
        let issuer = format!("{}/", issuer.trim().trim_end_matches('/'));
        let audience = std::env::var("AUTH0_AUDIENCE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or("Missing AUTH0_AUDIENCE")?;
        let jwks_uri = std::env::var("AUTH0_JWKS_URI")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("{issuer}.well-known/jwks.json"));
        if !issuer.starts_with("https://") || !jwks_uri.starts_with("https://") {
            return Err("Auth0 issuer and JWKS must use HTTPS");
        }
        Ok(Self {
            issuer,
            audience: audience.trim().into(),
            jwks_uri,
            claims_ns: std::env::var("AUTH0_CLAIMS_NS")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "https://kimanilife.com/claims".into())
                .trim()
                .trim_end_matches('/')
                .into(),
        })
    }
}

/// Injected key transport keeps network failure and rotation tests deterministic.
#[async_trait]
pub trait KeySource: Send + Sync {
    async fn fetch(&self) -> Result<JwkSet, ()>;
}

struct HttpKeys {
    client: reqwest::Client,
    uri: String,
}
#[async_trait]
impl KeySource for HttpKeys {
    async fn fetch(&self) -> Result<JwkSet, ()> {
        let response = self
            .client
            .get(&self.uri)
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?;
        if response.content_length().unwrap_or(0) > 65_536 {
            return Err(());
        }
        let bytes = response.bytes().await.map_err(|_| ())?;
        if bytes.len() > 65_536 {
            return Err(());
        }
        serde_json::from_slice(&bytes).map_err(|_| ())
    }
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
}

impl KeyCache {
    /// Returns the key for `kid` and whether it is still within the JWKS TTL;
    /// keys older than `JWKS_MAX_STALE` are treated as gone.
    fn get(&self, kid: &str, now: Instant) -> Option<(DecodingKey, bool)> {
        let age = now.duration_since(self.fetched_at?);
        if age >= JWKS_MAX_STALE {
            return None;
        }
        self.keys.get(kid).map(|key| (key.clone(), age < JWKS_TTL))
    }
}

/// Why a supplied proof grants nothing; logged, never shown to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Oversized,
    Malformed,
    Algorithm,
    UnknownKey,
    Invalid,
    AccountMismatch,
    Expired,
}

/// A verified proof is tied to the already authenticated Revolt account.
pub struct Authority {
    pub is_privileged: bool,
    pub expires_at: u64,
}

/// Cached public-key validation; never reads administrative flags from Mongo.
pub struct Verifier {
    config: Config,
    source: Arc<dyn KeySource>,
    /// Held only for map reads/swaps, never across the network fetch.
    cache: Mutex<KeyCache>,
    /// Single-flight JWKS refresh: one request fetches while the others use the last good keys.
    refresh: AsyncMutex<()>,
}
impl Verifier {
    /// Callers can inject a key source without replacing the JWT verification itself.
    pub fn new(config: Config, source: Arc<dyn KeySource>) -> Self {
        Self {
            config,
            source,
            cache: Mutex::new(KeyCache::default()),
            refresh: AsyncMutex::new(()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, KeyCache> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, Rejection> {
        let cached = self.cache().get(kid, Instant::now());
        if let Some((key, true)) = cached {
            return Ok(key);
        }
        let stale = cached.map(|(key, _)| key);
        // Someone else is refreshing: a known (stale) key is good enough, otherwise wait for them.
        let _refreshing = match self.refresh.try_lock() {
            Some(guard) => guard,
            None => match stale {
                Some(key) => return Ok(key),
                None => self.refresh.lock().await,
            },
        };
        let now = Instant::now();
        {
            let mut cache = self.cache();
            // A refresh may have completed while this request waited.
            if let Some((key, true)) = cache.get(kid, now) {
                return Ok(key);
            }
            // Unknown kid values must not turn an unauthenticated flood into a JWKS flood.
            if cache
                .attempted_at
                .map(|at| now.duration_since(at) < JWKS_REFRESH_MIN)
                .unwrap_or(false)
            {
                return cache
                    .get(kid, now)
                    .map(|(key, _)| key)
                    .ok_or(Rejection::UnknownKey);
            }
            cache.attempted_at = Some(now);
        }
        let set = match self.source.fetch().await {
            Ok(set) if set.keys.len() <= MAX_JWKS_KEYS => set,
            _ => {
                log::warn!("Auth0 JWKS refresh failed; keeping the last known keys");
                return self
                    .cache()
                    .get(kid, now)
                    .map(|(key, _)| key)
                    .ok_or(Rejection::UnknownKey);
            }
        };
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if let Some(id) = &jwk.common.key_id {
                if let Ok(key) = DecodingKey::from_jwk(jwk) {
                    keys.insert(id.clone(), key);
                }
            }
        }
        let mut cache = self.cache();
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.keys.get(kid).cloned().ok_or(Rejection::UnknownKey)
    }

    /// Verifies RS256, signature, expiry, issuer, audience, subject and the session/account binding.
    pub async fn verify(
        &self,
        token: &str,
        expected_account: &str,
    ) -> Result<Authority, Rejection> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Rejection::Oversized);
        }
        let header = decode_header(token).map_err(|_| Rejection::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(Rejection::Algorithm);
        }
        let kid = header
            .kid
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or(Rejection::Malformed)?;
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let claims = decode::<Value>(token, &key, &validation)
            .map_err(|e| match e.kind() {
                ErrorKind::ExpiredSignature => Rejection::Expired,
                _ => Rejection::Invalid,
            })?
            .claims;
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            return Err(Rejection::Invalid);
        }
        // Security binding, deliberately without a `sub` fallback: the proof must name this Revolt account.
        let user_key = format!("{}/user_id", self.config.claims_ns);
        if expected_account.is_empty()
            || claims.get(&user_key).and_then(Value::as_str) != Some(expected_account)
        {
            return Err(Rejection::AccountMismatch);
        }
        // Authorization is by permission, never by role name: Auth0 decides which roles carry it.
        let is_privileged = claims
            .get("permissions")
            .and_then(Value::as_array)
            .map(|permissions| {
                permissions
                    .iter()
                    .any(|p| p.as_str() == Some(PRIVILEGED_PERMISSION))
            })
            .unwrap_or(false);
        let expires_at = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or(Rejection::Invalid)?;
        if expires_at <= jsonwebtoken::get_current_timestamp() {
            return Err(Rejection::Expired);
        }
        Ok(Authority {
            is_privileged,
            expires_at,
        })
    }

    /// A proof that fails verification only withholds elevation; the Revolt session stays valid.
    /// Clients may send foreign or stale tokens (microservices HS tokens, expired Auth0 JWTs),
    /// and failing the whole request or socket for that locked members out of chat.
    pub async fn authority(
        &self,
        token: Option<&str>,
        expected_account: &str,
    ) -> Option<Authority> {
        match self.verify(token?, expected_account).await {
            Ok(authority) => Some(authority),
            Err(Rejection::AccountMismatch) => {
                log::warn!("Auth0 proof is bound to a different account than session user {expected_account}; ignored");
                None
            }
            Err(reason) => {
                log::debug!("Auth0 proof ignored for {expected_account}: {reason:?}");
                None
            }
        }
    }
}

static VERIFIER: Lazy<Option<Verifier>> = Lazy::new(|| http_verifier(Config::from_env()));

/// Builds the production verifier; a missing or invalid config disables elevation, not sessions.
fn http_verifier(config: Result<Config, &'static str>) -> Option<Verifier> {
    let built = config.and_then(|config| {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "Invalid Auth0 HTTP configuration")?;
        let source = Arc::new(HttpKeys {
            client,
            uri: config.jwks_uri.clone(),
        });
        Ok(Verifier::new(config, source))
    });
    match built {
        Ok(verifier) => Some(verifier),
        Err(reason) => {
            log::warn!("Auth0 verification disabled, no session will be elevated: {reason}");
            None
        }
    }
}

/// Normal sessions keep working without Auth0; only a valid proof for that session elevates it.
pub async fn authority(token: Option<&str>, expected_account: &str) -> Option<Authority> {
    token?;
    VERIFIER.as_ref()?.authority(token, expected_account).await
}

/// Extracts a Bearer token; any other `Authorization` value (e.g. Basic) is simply not a proof.
pub fn bearer(header: Option<&str>) -> Option<&str> {
    let (scheme, token) = header?.split_once(' ')?;
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        log::debug!("Ignoring a non-Bearer Authorization header");
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests;
