use crate::models::attachment::File;
use crate::models::events::guest::EventGuest;
use serde::{Deserialize, Serialize};

pub fn if_false(t: &bool) -> bool {
    !t
}

/// Representation of an event
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct EventHost {
    pub id: String,
    pub username: String,
    pub avatar: Option<File>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct EventGuestStats {
    pub total_invited: i32,
    pub total_going: i32,
    pub total_pending: i32,
    pub total_rejected: i32,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, OptionalStruct, Default)]
#[optional_derive(Serialize, Deserialize, JsonSchema, Debug, Default, Clone)]
#[optional_name = "PartialEvent"]
#[opt_skip_serializing_none]
#[opt_some_priority]
pub struct Event {
    /// Event Id
    #[serde(rename = "_id")]
    pub id: String,

    /// User who created the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,

    /// Event title
    pub title: String,

    /// Event type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<EventType>,

    /// Start date and time
    pub start_date: String,

    /// End date and time
    pub end_date: String,

    /// Timezone for the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,

    /// City where event is held
    pub city: String,

    /// Country where event is held
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// Whether the event is public or private
    #[serde(skip_serializing_if = "if_false", default)]
    pub hide_address: bool,

    /// Area/neighborhood
    pub area: String,

    /// Full address
    pub address: String,

    /// Event description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Allow +1 guests
    #[serde(skip_serializing_if = "if_false", default)]
    pub allow_plus_one: bool,

    /// Maximum number of +1 guests allowed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_plus_one_amount: Option<i32>,

    /// Require full information for +1 guests
    #[serde(skip_serializing_if = "if_false", default)]
    pub requires_plus_one_info: bool,

    /// Require RSVP approval by host
    #[serde(skip_serializing_if = "if_false", default)]
    pub requires_rsvp_approval: bool,

    /// Show events to non-members
    #[serde(skip_serializing_if = "if_false", default)]
    pub show_to_non_members: bool,

    /// Maximum number of attendees (overall capacity); None = unlimited
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<i32>,

    /// Event hosts with their details
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub hosts: Vec<String>,

    /// Resolved host details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_details: Option<Vec<EventHost>>,

    /// Event sponsors with their details
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sponsors: Vec<String>,

    /// Resolved sponsor details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sponsor_details: Option<Vec<EventHost>>,

    /// Ticket configuration
    pub ticket_config: TicketConfig,

    /// Currency type (e.g. "USD", "EUR")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Payment type (e.g. "Cash", "Card", "Both")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_type: Option<String>,

    /// Attachment URLs
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attachments: Vec<String>,

    /// Gallery image URLs
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub gallery: Vec<String>,

    /// Whether the event is saved by current user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_saved: Option<bool>,

    /// Creation timestamp
    pub created_at: String,

    /// List of guests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guests: Option<Vec<EventGuest>>,

    /// Guest statistics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_stats: Option<EventGuestStats>,

    /// Thumbnail image ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<String>,

    /// Counter for guests invited via bulk messages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_count: Option<i32>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub enum EventType {
    KimaniEvent,
    MembersEvent,
    Other,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct TicketConfig {
    /// Type of ticket (free or paid)
    pub is_paid: bool,
    /// Member ticket price (if paid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_price: Option<String>,
    /// Member ticket price currency (e.g. "USD", "EUR")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_price_currency: Option<String>,
    /// Maximum tickets for members
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_max_tickets: Option<i32>,
    /// Non-member ticket price (if paid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_member_price: Option<String>,
    /// Non-member ticket price currency (e.g. "USD", "EUR")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_member_price_currency: Option<String>,
    /// Maximum tickets for non-members
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_member_max_tickets: Option<i32>,
    /// Allow purchase of multiple tickets
    pub allow_multiple_tickets: bool,
    /// Processing fee percentage
    pub processing_fee_percentage: Option<String>,
}
