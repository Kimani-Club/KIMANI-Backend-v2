use std::collections::HashSet;

use revolt_quark::{
    models::{Member, User},
    perms, Db, Ref, Result,
};

use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};

/// # Query Parameters
#[derive(Deserialize, JsonSchema, FromForm)]
pub struct OptionsFetchAllMembers {
    /// Whether to exclude offline users
    exclude_offline: Option<bool>,
}

/// # Member List
///
/// Both lists are sorted by ID.
#[derive(Serialize, JsonSchema)]
pub struct AllMemberResponse {
    /// List of members
    members: Vec<Member>,
    /// List of users
    users: Vec<User>,
}

/// # Fetch Members
///
/// Fetch all server members.
#[openapi(tag = "Server Members")]
#[get("/<target>/members?<options..>")]
pub async fn req(
    db: &Db,
    user: User,
    target: Ref,
    options: OptionsFetchAllMembers,
) -> Result<Json<AllMemberResponse>> {
    let server = target.as_server(db).await?;
    perms(&user).server(&server).calc(db).await?;

    let mut members = db.fetch_all_members(&server.id).await?;

    let mut user_ids = vec![];
    for member in &members {
        user_ids.push(member.id.user.clone());
    }

    let mut users = User::fetch_foreign_users(db, &user_ids).await?;

    // Ensure the lists match up exactly.
    members.sort_by(|a, b| a.id.user.cmp(&b.id.user));
    users.sort_by(|a, b| a.id.cmp(&b.id));

    // Optionally, remove all offline user entries.
    if let Some(true) = options.exclude_offline {
        retain_online(&mut members, &mut users);
    }

    Ok(Json(AllMemberResponse { members, users }))
}

/// Keep only the members/users that are known to be online.
///
/// The two lists are NOT guaranteed to pair up one-to-one: a member's user
/// document can be missing or unreadable (`fetch_users` skips documents it
/// cannot deserialise, and orphaned member rows can outlive their user), so
/// matching is done by user id rather than by position. A member without a
/// fetched user is treated as offline and removed.
fn retain_online(members: &mut Vec<Member>, users: &mut Vec<User>) {
    let online: HashSet<&str> = users
        .iter()
        .filter(|user| user.online.unwrap_or(false))
        .map(|user| user.id.as_str())
        .collect();

    members.retain(|member| online.contains(member.id.user.as_str()));
    users.retain(|user| user.online.unwrap_or(false));
}

#[cfg(test)]
mod tests {
    use revolt_quark::models::server_member::MemberCompositeKey;
    use revolt_quark::Timestamp;

    use super::*;

    fn member(user_id: &str) -> Member {
        Member {
            id: MemberCompositeKey {
                server: "server".to_string(),
                user: user_id.to_string(),
            },
            joined_at: Timestamp::UNIX_EPOCH,
            nickname: None,
            avatar: None,
            roles: vec![],
            timeout: None,
        }
    }

    fn user(id: &str, online: bool) -> User {
        User {
            id: id.to_string(),
            online: Some(online),
            ..Default::default()
        }
    }

    fn member_ids(members: &[Member]) -> Vec<&str> {
        members.iter().map(|m| m.id.user.as_str()).collect()
    }

    fn user_ids(users: &[User]) -> Vec<&str> {
        users.iter().map(|u| u.id.as_str()).collect()
    }

    #[test]
    fn equal_lists_keep_only_online_entries() {
        let mut members = vec![member("a"), member("b"), member("c")];
        let mut users = vec![user("a", true), user("b", false), user("c", true)];

        retain_online(&mut members, &mut users);

        assert_eq!(member_ids(&members), vec!["a", "c"]);
        assert_eq!(user_ids(&users), vec!["a", "c"]);
    }

    #[test]
    fn fewer_users_than_members_does_not_panic() {
        // The pre-fix positional zip panicked on `iter.next().unwrap()` the
        // moment `users` ran out — the exact shape behind the post-reconnect
        // 500 (truncated `fetch_users` result / orphaned member row).
        let mut members = vec![member("a"), member("b"), member("c")];
        let mut users = vec![user("b", true)];

        retain_online(&mut members, &mut users);

        assert_eq!(member_ids(&members), vec!["b"]);
        assert_eq!(user_ids(&users), vec!["b"]);
    }

    #[test]
    fn more_users_than_members_does_not_panic() {
        let mut members = vec![member("b")];
        let mut users = vec![user("a", true), user("b", true), user("c", false)];

        retain_online(&mut members, &mut users);

        assert_eq!(member_ids(&members), vec!["b"]);
        // Users are filtered purely on their own online flag.
        assert_eq!(user_ids(&users), vec!["a", "b"]);
    }

    #[test]
    fn empty_lists_are_a_no_op() {
        let mut members: Vec<Member> = vec![];
        let mut users: Vec<User> = vec![];

        retain_online(&mut members, &mut users);

        assert!(members.is_empty());
        assert!(users.is_empty());
    }

    #[test]
    fn matching_is_by_id_not_position() {
        // Unsorted/mismatched ordering must not mis-associate online flags —
        // the old positional zip silently did when the lists diverged.
        let mut members = vec![member("c"), member("a"), member("b")];
        let mut users = vec![user("b", false), user("c", true), user("a", true)];

        retain_online(&mut members, &mut users);

        assert_eq!(member_ids(&members), vec!["c", "a"]);
        assert_eq!(user_ids(&users), vec!["c", "a"]);
    }

    #[test]
    fn missing_online_flag_counts_as_offline() {
        let mut members = vec![member("a"), member("b")];
        let mut users = vec![
            User {
                id: "a".to_string(),
                online: None,
                ..Default::default()
            },
            user("b", true),
        ];

        retain_online(&mut members, &mut users);

        assert_eq!(member_ids(&members), vec!["b"]);
        assert_eq!(user_ids(&users), vec!["b"]);
    }
}
