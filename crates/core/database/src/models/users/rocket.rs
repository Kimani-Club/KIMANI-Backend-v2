use authifier::models::Session;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Outcome, Request};

use crate::{Database, User};

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = authifier::Error;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let user: &Option<User> = request
            .local_cache_async(async {
                let db = request.rocket().state::<Database>().expect("`Database`");

                let _header_bot_token = request
                    .headers()
                    .get("x-bot-token")
                    .next()
                    .map(|x| x.to_string());

                /* if let Some(bot_token) = header_bot_token {
                    if let Ok(user) = User::from_token(db, &bot_token, UserHint::Bot).await {
                        return Some(user);
                    }
                } else */
                if let Outcome::Success(session) = request.guard::<Session>().await {
                    // This uses a guard so can't really easily be refactored into from_token at this stage.
                    if let Ok(user) = db.fetch_user(&session.user_id).await {
                        return Some(user);
                    }
                }

                None
            })
            .await;

        if let Some(user) = user {
            let mut user = user.clone();
            // An absent or unverifiable Auth0 proof only means "no elevation", never a failed request.
            let token = kimani_auth0::bearer(request.headers().get_one("Authorization"));
            let authority = kimani_auth0::authority(token, &user.id).await;
            user.privileged = user.bot.is_none() && authority.map(|a| a.is_privileged).unwrap_or(false);
            Outcome::Success(user)
        } else {
            Outcome::Failure((Status::Unauthorized, authifier::Error::InvalidSession))
        }
    }
}
