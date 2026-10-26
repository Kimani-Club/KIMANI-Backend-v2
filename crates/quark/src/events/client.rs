use authifier::AuthifierEvent;
use revolt_models::v0::{FieldsWebhook, PartialWebhook, Webhook};
use serde::{Deserialize, Serialize};

use crate::models::channel::{FieldsChannel, PartialChannel};
use crate::models::message::{AppendMessage, PartialMessage};
use crate::models::server::{FieldsRole, FieldsServer, PartialRole, PartialServer};
use crate::models::server_member::{FieldsMember, MemberCompositeKey, PartialMember};
use crate::models::user::{FieldsUser, PartialUser, RelationshipStatus};
use crate::models::{Channel, Emoji, Member, Message, Report, Server, User, UserSettings};
use crate::Error;

/// WebSocket Client Errors
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "error")]
pub enum WebSocketError {
    LabelMe,
    InternalError { at: String },
    InvalidSession,
    OnboardingNotFinished,
    AlreadyAuthenticated,
    MalformedData { msg: String },
}

/// Ping Packet
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Ping {
    Binary(Vec<u8>),
    Number(usize),
}

/// Untagged Error
#[derive(Serialize)]
#[serde(untagged)]
pub enum ErrorEvent {
    Error(WebSocketError),
    APIError(Error),
}

/// Protocol Events
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum EventV1 {
    /// Multiple events
    Bulk { v: Vec<EventV1> },

    /// Successfully authenticated
    Authenticated,

    /// Basic data to cache
    Ready {
        users: Vec<User>,
        servers: Vec<Server>,
        channels: Vec<Channel>,
        members: Vec<Member>,
        emojis: Option<Vec<Emoji>>,
    },

    /// Ping response
    Pong { data: Ping },

    /// New message
    Message(Message),

    /// Update existing message
    MessageUpdate {
        id: String,
        channel: String,
        data: PartialMessage,
    },

    /// Append information to existing message
    MessageAppend {
        id: String,
        channel: String,
        append: AppendMessage,
    },

    /// Delete message
    MessageDelete { id: String, channel: String },

    /// New reaction to a message
    MessageReact {
        id: String,
        channel_id: String,
        user_id: String,
        emoji_id: String,
    },

    /// Remove user's reaction from message
    MessageUnreact {
        id: String,
        channel_id: String,
        user_id: String,
        emoji_id: String,
    },

    /// Remove a reaction from message
    MessageRemoveReaction {
        id: String,
        channel_id: String,
        emoji_id: String,
    },

    /// Bulk delete messages
    BulkMessageDelete { channel: String, ids: Vec<String> },

    /// New channel
    ChannelCreate(Channel),

    /// Update existing channel
    ChannelUpdate {
        id: String,
        data: PartialChannel,
        clear: Vec<FieldsChannel>,
    },

    /// Delete channel
    ChannelDelete { id: String },

    /// User joins a group
    ChannelGroupJoin { id: String, user: String },

    /// User leaves a group
    ChannelGroupLeave { id: String, user: String },

    /// User started typing in a channel
    ChannelStartTyping { id: String, user: String },

    /// User stopped typing in a channel
    ChannelStopTyping { id: String, user: String },

    /// User acknowledged message in channel
    ChannelAck {
        id: String,
        user: String,
        message_id: String,
    },

    /// New server
    ServerCreate {
        id: String,
        server: Server,
        channels: Vec<Channel>,
    },

    /// Update existing server
    ServerUpdate {
        id: String,
        data: PartialServer,
        clear: Vec<FieldsServer>,
    },

    /// Delete server
    ServerDelete { id: String },

    /// Update existing server member
    ServerMemberUpdate {
        id: MemberCompositeKey,
        data: PartialMember,
        clear: Vec<FieldsMember>,
    },

    /// User joins server
    ServerMemberJoin { id: String, user: String },

    /// User left server
    ServerMemberLeave { id: String, user: String },

    /// Server role created or updated
    ServerRoleUpdate {
        id: String,
        role_id: String,
        data: PartialRole,
        clear: Vec<FieldsRole>,
    },

    /// Server role deleted
    ServerRoleDelete { id: String, role_id: String },

    /// Update existing user
    UserUpdate {
        id: String,
        data: PartialUser,
        clear: Vec<FieldsUser>,
        event_id: Option<String>,
    },

    /// Relationship with another user changed
    UserRelationship {
        id: String,
        user: User,
        // ! this field can be deprecated
        status: RelationshipStatus,
    },

    /// Settings updated remotely
    UserSettingsUpdate { id: String, update: UserSettings },

    /// User has been platform banned or deleted their account
    ///
    /// Clients should remove the following associated data:
    /// - Messages
    /// - DM Channels
    /// - Relationships
    /// - Server Memberships
    ///
    /// User flags are specified to explain why a wipe is occurring though not all reasons will necessarily ever appear.
    UserPlatformWipe { user_id: String, flags: i32 },

    /// New emoji
    EmojiCreate(Emoji),

    /// Delete emoji
    EmojiDelete { id: String },

    /// New webhook
    WebhookCreate(Webhook),

    /// Update existing webhook
    WebhookUpdate {
        id: String,
        data: PartialWebhook,
        remove: Vec<FieldsWebhook>,
    },

    /// Delete webhook
    WebhookDelete { id: String },

    /// New report
    ReportCreate(Report),

    /// Auth events
    Auth(AuthifierEvent),

    /// Signals Bonfire to immediately close this user's WebSocket connection.
    /// Published by external services (e.g. NestJS) to the {user_id}! private channel
    /// after revoking all sessions for a soft-deleted member.
    SessionRevoke,

    /// A trip shared from Destinations ("Travel post") was stored. Internal:
    /// published on the global topic for the microservices rewards listener,
    /// which reads the trip's owner from the database, never from here.
    TravelPostCreated { id: String },

    /// K Points were credited to this user. Published by the microservices
    /// rewards program to the {user_id}! private channel, so every connected
    /// client (web included, which has no push) refreshes its balance at once.
    PointsEarned { points: i64, action_type: String },
}

#[cfg(test)]
mod rewards_event_tests {
    use super::*;

    // The microservices listener matches on exactly this shape
    // (apps/notifications/src/listener/listener.controller.ts).
    #[test]
    fn travel_post_created_serializes_as_the_listener_expects() {
        let event = EventV1::TravelPostCreated {
            id: "6560f1c2a1b2c3d4e5f60718".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({
                "type": "TravelPostCreated",
                "id": "6560f1c2a1b2c3d4e5f60718"
            })
        );
    }

    // Published by microservices (libs/revolt/src/bonfire/bonfire-events.service.ts).
    #[test]
    fn points_earned_deserializes_from_the_microservices_payload() {
        let event: EventV1 = serde_json::from_str(
            r#"{"type":"PointsEarned","points":1000,"action_type":"travel_post"}"#,
        )
        .unwrap();
        assert!(matches!(
            event,
            EventV1::PointsEarned { points: 1000, ref action_type } if action_type == "travel_post"
        ));
    }

    // Bonfire decodes every Redis payload as an EventV1 and only warns
    // ("Failed to deserialise an event") when that fails. An event type this
    // build does not know yet must therefore be a plain decode error, never a
    // panic — that is what keeps a mixed-version rollout safe.
    #[test]
    fn an_unknown_event_type_is_a_decode_error_not_a_panic() {
        let decoded = serde_json::from_str::<EventV1>(
            r#"{"type":"SomethingFromTheFuture","points":1}"#,
        );
        assert!(decoded.is_err());
    }
}
