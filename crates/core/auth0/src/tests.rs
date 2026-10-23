use super::*;
use futures::lock::Mutex;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const SLOW_FETCH: Duration = Duration::from_millis(300);

struct Keys {
    set: Mutex<JwkSet>,
    calls: AtomicUsize,
    fail: AtomicBool,
    slow: AtomicBool,
}
#[async_trait]
impl KeySource for Keys {
    async fn fetch(&self) -> Result<JwkSet, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.slow.load(Ordering::SeqCst) {
            async_std::task::sleep(SLOW_FETCH).await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(());
        }
        Ok(self.set.lock().await.clone())
    }
}

/// Ages the cache past its TTL and backoff, as if the keys were fetched long ago.
fn expire_cache(verifier: &Verifier) {
    let mut cache = verifier.cache();
    let long_ago = Instant::now()
        .checked_sub(JWKS_TTL + Duration::from_secs(1))
        .unwrap();
    cache.fetched_at = Some(long_ago);
    cache.attempted_at = Some(long_ago);
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/key-fixture.json")).unwrap()
}
fn setup() -> (Verifier, Arc<Keys>) {
    let source = Arc::new(Keys {
        set: Mutex::new(serde_json::from_value(fixture()["jwks"].clone()).unwrap()),
        calls: AtomicUsize::new(0),
        fail: AtomicBool::new(false),
        slow: AtomicBool::new(false),
    });
    let verifier = Verifier::new(
        Config {
            issuer: "https://tenant.test/".into(),
            audience: "https://api.test".into(),
            claims_ns: "https://kimanilife.com/claims".into(),
            jwks_uri: "https://tenant.test/jwks".into(),
        },
        source.clone(),
    );
    (verifier, source)
}
fn claims() -> Value {
    json!({"iss":"https://tenant.test/", "aud":["https://api.test", "https://tenant.test/userinfo"],
        "sub":"auth0|subject", "exp":jsonwebtoken::get_current_timestamp()+300,
        "https://kimanilife.com/claims/user_id":"kimani-account",
        "https://kimanilife.com/claims/roles":["admin"], "permissions":["revolt:privileged"]})
}
fn sign_with_kid(claims: &Value, kid: &str) -> String {
    let der = fixture()["private_pkcs1_der"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(&header, claims, &EncodingKey::from_rsa_der(&der)).unwrap()
}
fn sign(claims: &Value) -> String {
    sign_with_kid(claims, "test-key")
}

#[async_std::test]
async fn a_valid_proof_is_bound_to_the_revolt_session_account() {
    let (verifier, _) = setup();
    let token = sign(&claims());
    assert!(
        verifier
            .verify(&token, "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
    assert!(verifier.verify(&token, "another-account").await.is_err());
}

#[async_std::test]
async fn standard_claims_are_required_and_checked() {
    let (verifier, _) = setup();
    for field in [
        "iss",
        "aud",
        "sub",
        "exp",
        "https://kimanilife.com/claims/user_id",
    ] {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(field);
        assert!(
            verifier.verify(&sign(&c), "kimani-account").await.is_err(),
            "missing {field}"
        );
    }
    for (field, value) in [
        ("iss", json!("https://other.test/")),
        ("aud", json!("other-api")),
        ("exp", json!(1)),
        ("nbf", json!(jsonwebtoken::get_current_timestamp() + 3600)),
        ("sub", json!("")),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(
            verifier.verify(&sign(&c), "kimani-account").await.is_err(),
            "invalid {field}"
        );
    }
}

#[async_std::test]
async fn legacy_flags_and_role_names_do_not_grant_privilege() {
    let (verifier, _) = setup();
    for permissions in [
        json!([]),
        json!(["communities:manage"]),
        json!("revolt:privileged"),
    ] {
        let mut c = claims();
        c["permissions"] = permissions;
        c["privileged"] = json!(true);
        c["roles"] = json!(["admin"]);
        assert!(
            !verifier
                .verify(&sign(&c), "kimani-account")
                .await
                .unwrap()
                .is_privileged
        );
    }
}

#[async_std::test]
async fn signature_and_algorithm_cannot_be_substituted() {
    let (verifier, _) = setup();
    let token = sign(&claims());
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(0..1, replacement);
    assert!(verifier
        .verify(&parts.join("."), "kimani-account")
        .await
        .is_err());
    let forged = encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_secret(b"fake"),
    )
    .unwrap();
    assert!(verifier.verify(&forged, "kimani-account").await.is_err());
}

#[async_std::test]
async fn keys_are_cached_and_unknown_kids_do_not_flood_the_tenant() {
    let (verifier, source) = setup();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    for _ in 0..10 {
        assert!(verifier
            .verify(&sign_with_kid(&claims(), "unknown"), "kimani-account")
            .await
            .is_err());
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
}

#[async_std::test]
async fn rotation_fetches_the_new_key_after_the_refresh_backoff() {
    let (verifier, source) = setup();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    source.set.lock().await.keys[0].common.key_id = Some("rotated".into());
    verifier.cache().attempted_at = None;
    assert!(
        verifier
            .verify(&sign_with_kid(&claims(), "rotated"), "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[async_std::test]
async fn normal_sessions_need_no_auth0_config_or_network() {
    assert!(authority(None, "ordinary-member").await.is_none());
    assert_eq!(bearer(None), None);
}

#[test]
fn non_bearer_authorization_headers_are_not_proofs() {
    assert_eq!(bearer(Some("Basic dXNlcjpwYXNz")), None);
    assert_eq!(bearer(Some("Bearer ")), None);
    assert_eq!(bearer(Some("Bearer")), None);
    assert_eq!(bearer(Some("Bearer abc.def.ghi")), Some("abc.def.ghi"));
    assert_eq!(bearer(Some("bearer abc.def.ghi")), Some("abc.def.ghi"));
}

#[test]
fn a_missing_auth0_config_disables_elevation_instead_of_failing() {
    // Built from an explicit config error, never from the process environment or the network.
    assert!(http_verifier(Err("Missing AUTH0_ISSUER or AUTH0_DOMAIN")).is_none());
}

#[async_std::test]
async fn unverifiable_proofs_withhold_elevation_without_failing() {
    let (verifier, _) = setup();
    let mut expired = claims();
    expired["exp"] = json!(jsonwebtoken::get_current_timestamp() - 60);
    let hs_microservices_token = encode(
        &Header::new(Algorithm::HS256),
        &json!({"sub": "kimani-account", "exp": jsonwebtoken::get_current_timestamp() + 300}),
        &EncodingKey::from_secret(b"microservices-secret"),
    )
    .unwrap();
    let cases = [
        ("garbage", "not-a-jwt".to_string(), Rejection::Malformed),
        (
            "foreign HS token",
            hs_microservices_token,
            Rejection::Algorithm,
        ),
        ("expired", sign(&expired), Rejection::Expired),
        (
            "unknown kid",
            sign_with_kid(&claims(), "unknown"),
            Rejection::UnknownKey,
        ),
    ];
    for (name, token, reason) in cases {
        assert_eq!(
            verifier.verify(&token, "kimani-account").await.err(),
            Some(reason),
            "{name}"
        );
        assert!(
            verifier
                .authority(Some(&token), "kimani-account")
                .await
                .is_none(),
            "{name}"
        );
    }
    assert!(verifier.authority(None, "kimani-account").await.is_none());
    assert!(
        verifier
            .authority(Some(&sign(&claims())), "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
}

#[async_std::test]
async fn a_proof_for_another_account_is_ignored_without_a_sub_fallback() {
    let (verifier, _) = setup();
    let mut c = claims();
    // `sub` matching the session must not stand in for the missing user_id binding.
    c["sub"] = json!("kimani-account");
    c.as_object_mut()
        .unwrap()
        .remove("https://kimanilife.com/claims/user_id");
    assert_eq!(
        verifier.verify(&sign(&c), "kimani-account").await.err(),
        Some(Rejection::AccountMismatch)
    );
    assert!(verifier
        .authority(Some(&sign(&claims())), "another-account")
        .await
        .is_none());
}

#[async_std::test]
async fn a_failed_jwks_refresh_keeps_the_last_good_keys() {
    let (verifier, source) = setup();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    expire_cache(&verifier);
    source.fail.store(true, Ordering::SeqCst);
    assert!(verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .is_ok());
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[async_std::test]
async fn a_slow_jwks_refresh_does_not_block_readers_with_known_keys() {
    let (verifier, source) = setup();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    expire_cache(&verifier);
    source.slow.store(true, Ordering::SeqCst);
    let token = sign(&claims());
    let refresher = verifier.verify(&token, "kimani-account");
    let reader = async {
        let started = Instant::now();
        let result = verifier.verify(&token, "kimani-account").await;
        (result.is_ok(), started.elapsed())
    };
    let (refreshed, (read_ok, read_took)) = futures::join!(refresher, reader);
    assert!(refreshed.is_ok());
    assert!(read_ok);
    assert!(
        read_took < SLOW_FETCH,
        "reader waited {read_took:?} for the refresh"
    );
    // Single flight: the initial fetch plus exactly one refresh.
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[async_std::test]
async fn privilege_comes_from_the_permission_whatever_the_role() {
    let (verifier, _) = setup();
    let mut staff = claims();
    staff["https://kimanilife.com/claims/roles"] = json!(["staff"]);
    assert!(
        verifier
            .verify(&sign(&staff), "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
    let mut admin_without_permission = claims();
    admin_without_permission
        .as_object_mut()
        .unwrap()
        .remove("permissions");
    assert!(
        !verifier
            .verify(&sign(&admin_without_permission), "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
}

#[async_std::test]
async fn last_good_keys_stop_working_after_the_max_stale_age() {
    let (verifier, source) = setup();
    verifier
        .verify(&sign(&claims()), "kimani-account")
        .await
        .unwrap();
    source.fail.store(true, Ordering::SeqCst);
    {
        let mut cache = verifier.cache();
        let too_old = Instant::now()
            .checked_sub(JWKS_MAX_STALE + Duration::from_secs(1))
            .unwrap();
        cache.fetched_at = Some(too_old);
        cache.attempted_at = Some(too_old);
    }
    let token = sign(&claims());
    assert_eq!(
        verifier.verify(&token, "kimani-account").await.err(),
        Some(Rejection::UnknownKey)
    );
    assert!(verifier
        .authority(Some(&token), "kimani-account")
        .await
        .is_none());
}
