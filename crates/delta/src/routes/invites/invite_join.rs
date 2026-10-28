use revolt_quark::{
    models::{Channel, Invite, Server, User},
    variables::delta::MAX_SERVER_COUNT,
    Db, Error, Ref, Result,
};

use rocket::serde::json::Json;
use serde::Serialize;

/// # Join Response
#[derive(Serialize, JsonSchema)]
#[serde(tag = "type")]
pub enum InviteJoinResponse {
    Server {
        /// Channels in the server
        channels: Vec<Channel>,
        /// Server we are joining
        server: Server,
    },
}

/// # Join Invite
///
/// Join an invite by its ID.
#[openapi(tag = "Invites")]
#[post("/<target>")]
pub async fn req(db: &Db, user: User, target: Ref) -> Result<Json<InviteJoinResponse>> {
    if user.bot.is_some() {
        return Err(Error::IsBot);
    }

    refuse_restricted(&user)?;

    if !user.can_acquire_server(db).await? {
        return Err(Error::TooManyServers {
            max: *MAX_SERVER_COUNT,
        });
    }

    let invite = target.as_invite(db).await?;
    match &invite {
        Invite::Server { server, .. } => {
            let server = db.fetch_server(server).await?;
            let channels = server.create_member(db, user, None).await?;
            Ok(Json(InviteJoinResponse::Server { channels, server }))
        }
        _ => unreachable!(),
    }
}

/// A restricted member cannot join new servers; the invite simply looks
/// unknown so the response reveals nothing about the server.
fn refuse_restricted(user: &User) -> Result<()> {
    if user.is_restricted_actor() {
        Err(Error::NotFound)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use revolt_quark::models::user::Flags;

    use super::*;

    #[test]
    fn restricted_member_cannot_join_but_staff_can() {
        let restricted = User {
            flags: Some(Flags::Restricted as i32),
            ..Default::default()
        };
        assert!(matches!(refuse_restricted(&restricted), Err(Error::NotFound)));

        let staff = User {
            privileged: true,
            ..restricted
        };
        assert!(refuse_restricted(&staff).is_ok());
        assert!(refuse_restricted(&User::default()).is_ok());
    }
}
