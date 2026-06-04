use revolt_quark::{models::User, perms, Database, Error, Ref, Result};

use rocket::{serde::json::Json, State};

/// # Fetch User
///
/// Retrieve a user's information.
#[openapi(tag = "User Information")]
#[get("/<target>")]
pub async fn req(db: &State<Database>, user: User, target: Ref) -> Result<Json<User>> {
    if target.id == user.id {
        return Ok(Json(user));
    }

    let target = target.as_user(db).await?;

    // Block access to suspended (soft-deleted) profiles for other users.
    // Suspended flag is bit 0 (value = 1); NestJS sets flags = 1 to deactivate.
    if target.flags.unwrap_or(0) & 1 != 0 {
        return Err(Error::NotFound);
    }

    let permissions = perms(&user).user(&target).calc_user(db).await;
    if permissions.get_access() {
        Ok(Json(target.with_perspective(&user, &permissions)))
    } else {
        Err(Error::NotFound)
    }
}
