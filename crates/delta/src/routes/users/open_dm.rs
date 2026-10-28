use revolt_quark::{
    models::{channel::PartialChannel, Channel, User},
    perms, Database, Error, Ref, Result, UserPermission,
};

use rocket::{serde::json::Json, State};
use ulid::Ulid;

/// # Open Direct Message
///
/// Open a DM with another user.
///
/// If the target is oneself, a saved messages channel is returned.
/// Privileged staff open a staff DM with anyone; restricted members can't open new DMs.
#[openapi(tag = "Direct Messaging")]
#[get("/<target>/dm")]
pub async fn req(db: &State<Database>, user: User, target: Ref) -> Result<Json<Channel>> {
    let target = target.as_user(db).await?;

    // If the target is oneself, open saved messages.
    if target.id == user.id {
        return if let Ok(channel) = db.find_direct_message_channel(&user.id, &target.id).await {
            Ok(Json(channel))
        } else {
            let new_channel = Channel::SavedMessages {
                id: Ulid::new().to_string(),
                user: user.id,
            };

            new_channel.create(db).await?;
            Ok(Json(new_channel))
        };
    }

    // Staff (Auth0 `revolt:privileged`) may open a DM with any member, and the
    // DM is marked so the member can always reply (see quark `calc`).
    let staff_id = staff_id_for(&user);

    // Otherwise try to find or create a DM.
    if let Ok(mut channel) = db.find_direct_message_channel(&user.id, &target.id).await {
        if staff_id.is_some() && channel.staff_id().is_none() {
            channel
                .update(
                    db,
                    PartialChannel {
                        staff_id,
                        ..Default::default()
                    },
                    vec![],
                )
                .await?;
        }

        Ok(Json(channel))
    } else if staff_id.is_some()
        || perms(&user)
            .user(&target)
            .calc_user(db)
            .await
            .get_send_message()
    {
        let new_channel = Channel::DirectMessage {
            id: Ulid::new().to_string(),
            active: false,
            recipients: vec![user.id, target.id],
            last_message_id: None,
            staff_id,
        };

        new_channel.create(db).await?;
        Ok(Json(new_channel))
    } else if target.is_restricted() {
        // Shadowed: answer as if the member did not exist.
        Err(Error::UnknownUser)
    } else {
        Error::from_user_permission(UserPermission::SendMessage)
    }
}

/// The `staff_id` a DM opened by `user` carries: their id when they are
/// privileged staff (bots never are).
fn staff_id_for(user: &User) -> Option<String> {
    (user.privileged && user.bot.is_none()).then(|| user.id.clone())
}

#[cfg(test)]
mod tests {
    use revolt_quark::models::user::BotInformation;

    use super::*;

    #[test]
    fn only_privileged_humans_mark_a_staff_dm() {
        let member = User {
            id: "member".into(),
            ..Default::default()
        };
        assert_eq!(staff_id_for(&member), None);

        let staff = User {
            privileged: true,
            ..member.clone()
        };
        assert_eq!(staff_id_for(&staff).as_deref(), Some("member"));

        let bot = User {
            bot: Some(BotInformation {
                owner: "owner".into(),
            }),
            ..staff
        };
        assert_eq!(staff_id_for(&bot), None);
    }
}
