use revolt_quark::models::user::User;
use revolt_quark::{Database, Result};
use rocket::State;

use super::event_guests::check_event_manager;

/// Delete event
#[openapi(tag = "Events")]
#[delete("/<id>")]
pub async fn delete_event(db: &State<Database>, user: User, id: String) -> Result<()> {
    // Only the event's organisers (or a Kimani admin) may delete it.
    let event = db.fetch_event(Some(&user.id), &id).await?;
    check_event_manager(db, &event, &user).await?;

    db.delete_event(&id).await?;
    Ok(())
}
