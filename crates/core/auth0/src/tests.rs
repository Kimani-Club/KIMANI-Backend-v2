use super::*;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Keys {
    set: Mutex<JwkSet>,
    calls: AtomicUsize,
}
#[async_trait]
impl KeySource for Keys {
    async fn fetch(&self) -> Result<JwkSet, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.set.lock().await.clone())
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("../tests/key-fixture.json")).unwrap()
}
fn setup() -> (Verifier, Arc<Keys>) {
    let source = Arc::new(Keys {
        set: Mutex::new(serde_json::from_value(fixture()["jwks"].clone()).unwrap()),
        calls: AtomicUsize::new(0),
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
async fn valid_admin_is_bound_to_the_revolt_session_account() {
    let (verifier, _) = setup();
    let token = sign(&claims());
    assert!(
        verifier
            .verify(&token, "kimani-account")
            .await
            .unwrap()
            .is_admin
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
async fn legacy_flags_and_other_roles_do_not_grant_admin() {
    let (verifier, _) = setup();
    for roles in [
        json!([]),
        json!(["staff"]),
        json!(["ambassador"]),
        json!(["member"]),
        json!("admin"),
    ] {
        let mut c = claims();
        c["https://kimanilife.com/claims/roles"] = roles;
        c["privileged"] = json!(true);
        c["roles"] = json!(["admin"]);
        assert!(
            !verifier
                .verify(&sign(&c), "kimani-account")
                .await
                .unwrap()
                .is_admin
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
    verifier.cache.lock().await.attempted_at = None;
    assert!(
        verifier
            .verify(&sign_with_kid(&claims(), "rotated"), "kimani-account")
            .await
            .unwrap()
            .is_admin
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
}

#[async_std::test]
async fn normal_sessions_need_no_auth0_config_or_network() {
    assert!(authority(None, "ordinary-member").await.unwrap().is_none());
    assert_eq!(bearer(None).unwrap(), None);
    assert!(bearer(Some("Basic fake")).is_err());
    assert!(bearer(Some("Bearer ")).is_err());
}

#[async_std::test]
async fn admin_role_alone_does_not_enable_the_deferred_user_editing_task() {
    let (verifier, _) = setup();
    let mut c = claims();
    c.as_object_mut().unwrap().remove("permissions");
    let authority = verifier.verify(&sign(&c), "kimani-account").await.unwrap();
    assert!(authority.is_admin);
    assert!(!authority.is_privileged);
    assert!(
        verifier
            .verify(&sign(&claims()), "kimani-account")
            .await
            .unwrap()
            .is_privileged
    );
}
