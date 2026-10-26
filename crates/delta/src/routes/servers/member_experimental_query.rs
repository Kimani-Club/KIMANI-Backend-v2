use std::collections::HashMap;

use revolt_quark::{
    models::{Member, User},
    perms, Db, Error, Ref, Result,
};

use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};

/// # Query Parameters
#[derive(Deserialize, JsonSchema, FromForm)]
pub struct OptionsQueryMembers {
    /// String to search for
    query: String,

    /// Discourage use of this API
    experimental_api: bool,
}

/// # Query members by name
#[derive(Serialize, JsonSchema)]
pub struct MemberQueryResponse {
    /// List of members
    members: Vec<Member>,
    /// List of users
    users: Vec<User>,
}

/// # Query members by name
///
/// Query members by a given name, this API is not stable and will be removed in the future.
#[openapi(tag = "Server Members")]
#[get("/<target>/members_experimental_query?<options..>")]
pub async fn member_experimental_query(
    db: &Db,
    user: User,
    target: Ref,
    options: OptionsQueryMembers,
) -> Result<Json<MemberQueryResponse>> {
    if !options.experimental_api {
        return Err(Error::InternalError);
    }

    let server = target.as_server(db).await?;
    perms(&user).server(&server).calc(db).await?;

    let members = db.fetch_all_members(&server.id).await?;

    let mut user_ids = vec![];
    for member in &members {
        user_ids.push(member.id.user.clone());
    }

    let mut users = User::fetch_foreign_users(db, &user_ids).await?;

    // Shadow restricted members from non-privileged viewers.
    User::retain_visible(&user, &mut users);

    // Filter all matches
    let mut zipped_vec: Vec<(Member, User)> = pair_by_user_id(members, users)
        .into_iter()
        .filter(|(member, user)| {
            if let Some(nickname) = &member.nickname {
                nickname.contains(&options.query)
            } else {
                user.username.contains(&options.query)
            }
        })
        .collect();

    // Sort remaining matches by length
    zipped_vec.sort_by(|(member_a, user_a), (member_b, user_b)| {
        let left = member_a.nickname.as_ref().unwrap_or(&user_a.username);
        let right = member_b.nickname.as_ref().unwrap_or(&user_b.username);
        left.len().cmp(&right.len())
    });

    // Take the first ten and return them
    let (members, users) = zipped_vec.into_iter().take(10).unzip();
    Ok(Json(MemberQueryResponse { members, users }))
}

/// Pair each member with its user by id, dropping members without a user.
///
/// The user list can be shorter than the member list (`fetch_users` skips
/// suspended and unreadable documents, and `retain_visible` drops restricted
/// users), so a positional zip paired members with the wrong users as soon
/// as one was missing.
fn pair_by_user_id(members: Vec<Member>, users: Vec<User>) -> Vec<(Member, User)> {
    let mut users: HashMap<String, User> =
        users.into_iter().map(|user| (user.id.clone(), user)).collect();

    members
        .into_iter()
        .filter_map(|member| {
            users
                .remove(&member.id.user)
                .map(|user| (member, user))
        })
        .collect()
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

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn missing_user_does_not_shift_the_pairs() {
        let members = vec![member("a"), member("b"), member("c")];
        let users = vec![user("a"), user("c")];

        let pairs = pair_by_user_id(members, users);

        let ids: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(m, u)| (m.id.user.as_str(), u.id.as_str()))
            .collect();
        assert_eq!(ids, vec![("a", "a"), ("c", "c")]);
    }
}
