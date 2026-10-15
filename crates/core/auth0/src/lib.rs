//! Auth0 is the only source of platform authority. Mongo remains the profile store.
use async_trait::async_trait;
use futures::lock::Mutex;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

const JWKS_TTL: Duration = Duration::from_secs(600);
const JWKS_REFRESH_MIN: Duration = Duration::from_secs(30);
const MAX_TOKEN_BYTES: usize = 32_768;

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

/// A verified proof is tied to the already authenticated Revolt account.
pub struct Authority {
    pub is_admin: bool,
    pub is_privileged: bool,
    pub expires_at: u64,
}

/// Cached public-key validation; never reads administrative flags from Mongo.
pub struct Verifier {
    config: Config,
    source: Arc<dyn KeySource>,
    cache: Mutex<KeyCache>,
}
impl Verifier {
    /// Callers can inject a key source without replacing the JWT verification itself.
    pub fn new(config: Config, source: Arc<dyn KeySource>) -> Self {
        Self {
            config,
            source,
            cache: Mutex::new(KeyCache::default()),
        }
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, ()> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        let fresh = cache
            .fetched_at
            .map(|at| now.duration_since(at) < JWKS_TTL)
            .unwrap_or(false);
        if fresh {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(key.clone());
            }
        }
        // Unknown kid values must not turn an unauthenticated flood into a JWKS flood.
        if cache
            .attempted_at
            .map(|at| now.duration_since(at) < JWKS_REFRESH_MIN)
            .unwrap_or(false)
        {
            return Err(());
        }
        cache.attempted_at = Some(now);
        let set = self.source.fetch().await?;
        if set.keys.len() > 100 {
            return Err(());
        }
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if let Some(id) = &jwk.common.key_id {
                if let Ok(key) = DecodingKey::from_jwk(jwk) {
                    keys.insert(id.clone(), key);
                }
            }
        }
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.keys.get(kid).cloned().ok_or(())
    }

    /// Verifies RS256, signature, expiry, issuer, audience, subject and the session/account binding.
    pub async fn verify(&self, token: &str, expected_account: &str) -> Result<Authority, ()> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(());
        }
        let header = decode_header(token).map_err(|_| ())?;
        if header.alg != Algorithm::RS256 {
            return Err(());
        }
        let kid = header
            .kid
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or(())?;
        let key = self.key(&kid).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let claims = decode::<Value>(token, &key, &validation)
            .map_err(|_| ())?
            .claims;
        if claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .is_none()
        {
            return Err(());
        }
        let user_key = format!("{}/user_id", self.config.claims_ns);
        if expected_account.is_empty()
            || claims.get(&user_key).and_then(Value::as_str) != Some(expected_account)
        {
            return Err(());
        }
        let role_key = format!("{}/roles", self.config.claims_ns);
        let is_admin = claims
            .get(&role_key)
            .and_then(Value::as_array)
            .map(|roles| roles.iter().any(|r| r.as_str() == Some("admin")))
            .unwrap_or(false);
        // This stage migrates existing powers; enabling user editing for every admin is a separate task.
        let is_privileged = is_admin
            && claims
                .get("permissions")
                .and_then(Value::as_array)
                .map(|permissions| {
                    permissions
                        .iter()
                        .any(|p| p.as_str() == Some("revolt:privileged"))
                })
                .unwrap_or(false);
        let expires_at = claims.get("exp").and_then(Value::as_u64).ok_or(())?;
        if expires_at <= jsonwebtoken::get_current_timestamp() {
            return Err(());
        }
        Ok(Authority {
            is_admin,
            is_privileged,
            expires_at,
        })
    }
}

static VERIFIER: Lazy<Result<Verifier, &'static str>> = Lazy::new(|| {
    let config = Config::from_env()?;
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

/// Normal sessions keep working without Auth0; a supplied proof must validate and match that session.
pub async fn authority(
    token: Option<&str>,
    expected_account: &str,
) -> Result<Option<Authority>, ()> {
    match token {
        None => Ok(None),
        Some(token) => VERIFIER
            .as_ref()
            .map_err(|_| ())?
            .verify(token, expected_account)
            .await
            .map(Some),
    }
}

/// Header parsing rejects malformed proofs instead of silently downgrading them.
pub fn bearer(header: Option<&str>) -> Result<Option<&str>, ()> {
    match header {
        None => Ok(None),
        Some(value) => {
            let token = value
                .strip_prefix("Bearer ")
                .filter(|s| !s.is_empty())
                .ok_or(())?;
            Ok(Some(token))
        }
    }
}

#[cfg(test)]
mod tests;
