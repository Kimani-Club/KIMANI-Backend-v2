use revolt_quark::models::event::{Event, EventType, PartialEvent, TicketConfig};
use revolt_quark::models::user::User;
use revolt_quark::{Database, Result};
use rocket::{serde::json::Json, State};
use serde::Deserialize;
use validator::Validate;

use super::event_guests::check_event_manager;

impl From<DataEditEvent> for PartialEvent {
    fn from(data: DataEditEvent) -> Self {
        Self {
            id: None,
            created_by: None,
            created_at: None,
            title: data.title,
            event_type: data.event_type,
            start_date: data.start_date,
            end_date: data.end_date,
            city: data.city,
            area: data.area,
            address: data.address,
            description: data.description,
            hide_address: data.hide_address,
            allow_plus_one: data.allow_plus_one,
            allow_plus_one_amount: data.allow_plus_one_amount,
            requires_plus_one_info: data.requires_plus_one_info,
            requires_rsvp_approval: data.requires_rsvp_approval,
            show_to_non_members: data.show_to_non_members,
            capacity: data.capacity,
            hosts: data.hosts,
            sponsors: data.sponsors,
            ticket_config: data.ticket_config,
            currency: data.currency,
            payment_type: data.payment_type,
            attachments: data.attachments,
            gallery: data.gallery,
            is_saved: None,
            host_details: None,
            sponsor_details: None,
            guests: None,
            guest_stats: None,
            thumbnail: data.thumbnail,
            country: data.country,
            timezone: data.timezone,
            invited_count: None,
        }
    }
}
#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataEditEvent {
    pub title: Option<String>,
    pub event_type: Option<EventType>,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub city: Option<String>,
    pub area: Option<String>,
    pub address: Option<String>,
    pub description: Option<String>,
    pub hide_address: Option<bool>,
    pub allow_plus_one: Option<bool>,
    pub allow_plus_one_amount: Option<i32>,
    pub requires_plus_one_info: Option<bool>,
    pub requires_rsvp_approval: Option<bool>,
    pub show_to_non_members: Option<bool>,
    pub capacity: Option<i32>,
    pub hosts: Option<Vec<String>>,
    pub sponsors: Option<Vec<String>>,
    pub ticket_config: Option<TicketConfig>,
    /// Attachment URLs
    pub attachments: Option<Vec<String>>,
    /// Gallery image URLs
    pub gallery: Option<Vec<String>>,
    pub currency: Option<String>,
    pub payment_type: Option<String>,
    /// Thumbnail image ID
    pub thumbnail: Option<String>,
    /// Country where event is held
    pub country: Option<String>,
    /// Timezone
    pub timezone: Option<String>,
}

/// Update event
#[openapi(tag = "Events")]
#[patch("/<id>", data = "<data>")]
pub async fn update_event(
    db: &State<Database>,
    user: User,
    id: String,
    data: Json<DataEditEvent>,
) -> Result<Json<Event>> {
    // Only the event's organisers (or a Kimani admin) may edit it.
    let existing = db.fetch_event(Some(&user.id), &id).await?;
    check_event_manager(db, &existing, &user).await?;

    db.update_event(&id, &data.into_inner().into()).await?;
    let event = db.fetch_event(Some(&user.id), &id).await?;
    Ok(Json(event))
}
