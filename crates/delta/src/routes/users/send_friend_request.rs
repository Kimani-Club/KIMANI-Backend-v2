use revolt_quark::models::User;
use revolt_quark::{Database, Error, Result};

use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};

/// Same short free-text cap already used for `UserStatus.text` (custom
/// status) — a friend request note is the same kind of short personal blurb,
/// not a message, so it reuses that limit rather than the 2000-char message
/// content cap.
const NOTE_MAX_LENGTH: usize = 128;

/// # User Lookup Information
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct DataSendFriendRequest {
    /// Target user ID (the existing API field is named username)
    username: String,
    /// Optional note shown to the recipient alongside the request
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// # Send Friend Request
///
/// Send a friend request to another user.
#[openapi(tag = "Relationships")]
#[post("/friend", data = "<data>")]
pub async fn req(
    db: &State<Database>,
    user: User,
    data: Json<DataSendFriendRequest>,
) -> Result<Json<User>> {
    if let username = &data.username {
        let mut target = db.fetch_user(&username).await?;

        if user.bot.is_some() || target.bot.is_some() {
            return Err(Error::IsBot);
        }

        let note = normalize_note(data.note.as_deref())?;

        user.add_friend(db, &mut target, note).await?;
        Ok(Json(target.with_auto_perspective(db, &user).await))
    } else {
        Err(Error::InvalidProperty)
    }
}

fn normalize_note(note: Option<&str>) -> Result<Option<String>> {
    let note = note.map(str::trim).filter(|note| !note.is_empty());
    if note.map_or(false, |note| note.chars().count() > NOTE_MAX_LENGTH) {
        return Err(Error::InvalidProperty);
    }
    Ok(note.map(str::to_owned))
}

#[cfg(test)]
mod friend_request_tests {
    use super::*;

    #[test]
    fn optional_note_validation() {
        assert_eq!(normalize_note(None).unwrap(), None);
        assert_eq!(normalize_note(Some(" \n ")).unwrap(), None);
        assert_eq!(
            normalize_note(Some(" hi\nthere ")).unwrap(),
            Some("hi\nthere".into())
        );
        assert!(normalize_note(Some(&"é".repeat(128))).is_ok());
        assert!(normalize_note(Some(&"é".repeat(129))).is_err());
        let request: DataSendFriendRequest =
            serde_json::from_str(r#"{"username":"recipient"}"#).unwrap();
        assert!(request.note.is_none());
    }
}
