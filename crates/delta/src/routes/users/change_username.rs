use crate::util::regex::RE_USERNAME;
use revolt_quark::{models::User, Database, Error, Result};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// # Username Information
#[derive(Validate, Serialize, Deserialize, JsonSchema)]
pub struct DataChangeUsername {
    /// New username
    #[validate(length(min = 2, max = 32), regex = "RE_USERNAME")]
    username: String,
}

/// # Change Username
///
/// Change your username. KIMANI members sign in with Auth0 and have no
/// password (their accounts carry a placeholder one), so the authenticated
/// session is the proof; a `password` sent by an older app is ignored.
#[openapi(tag = "User Information")]
#[patch("/@me/username", data = "<data>")]
pub async fn req(
    db: &State<Database>,
    mut user: User,
    data: Json<DataChangeUsername>,
) -> Result<Json<User>> {
    let data = data.into_inner();
    data.validate()
        .map_err(|error| Error::FailedValidation { error })?;

    user.update_username(db, data.username).await?;
    Ok(Json(user.foreign()))
}
