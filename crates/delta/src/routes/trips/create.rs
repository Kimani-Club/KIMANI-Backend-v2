use revolt_database::mongodb::bson::oid::ObjectId;
use revolt_database::trips::model::Trip;
use revolt_database::{Database, DatabaseTrait};
use revolt_quark::events::client::EventV1;
use revolt_quark::models::User;
use revolt_result::Result;
use revolt_rocket_okapi::openapi;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{post, State};

/// Create a new trip
///
/// Creates a new trip using the authenticated user's ID.
#[openapi]
#[post("/create", format = "json", data = "<trip>")]
pub async fn create_trip(db: &State<Database>, user: User, trip: Json<Trip>) -> Result<Status> {
    // The id is the server's, never the client's: the rewards program keys
    // its one-time "Travel post" award on it.
    let id = ObjectId::new();
    let trip = Trip {
        id: Some(id),
        user_id: user.id,
        ..trip.into_inner()
    };

    // Insert trip will handle marking other trips as deleted
    db.insert_trip(&trip).await?;

    // Only a stored trip is announced, so a failed create earns nothing.
    EventV1::TravelPostCreated { id: id.to_hex() }.global().await;

    Ok(Status::Created)
}
