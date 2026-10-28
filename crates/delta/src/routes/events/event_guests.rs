use revolt_quark::authifier::config::{EmailVerificationConfig, Template};
use revolt_quark::authifier::Authifier;
use revolt_quark::{
    models::channels::channel::{Channel, PartialChannel},
    models::channels::message::Message,
    models::events::event::{Event, PartialEvent},
    models::events::guest::{EventGuest, GuestStatus},
    models::user::User,
    types::push::MessageAuthor,
    variables::delta::APP_URL,
    perms, Database, Error, Result, UserPermission,
};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ulid::Ulid;
use validator::Validate;

#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataCreateGuest {
    /// Guest's full name
    #[validate(length(min = 1, max = 100))]
    pub name: String,
    /// Guest's email
    #[validate(email)]
    pub email: String,
    /// Guest's phone number
    pub phone: String,
    /// Associated user ID if the guest is a registered user
    pub associated_user_id: Option<String>,
    /// If this guest is a plus one of another guest
    pub plus_one_of: Option<String>,
    /// If this guest is a child guest (for pricing)
    pub parent_guest_id: Option<String>,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct DataCreateBulkGuests {
    /// Main contact guest. Required without a session; ignored with one,
    /// where the main contact is built from the signed-in account instead.
    #[serde(default)]
    pub main_contact: Option<DataCreateGuest>,
    /// Additional guests
    pub additional_guests: Vec<DataCreateGuest>,
}

#[derive(Serialize, JsonSchema)]
pub struct GuestResponse {
    guest: EventGuest,
}

#[derive(Serialize, JsonSchema)]
pub struct BulkGuestResponse {
    guests: Vec<EventGuest>,
}

/// Contact details of the signed-in member, as a registration would record them
#[derive(Serialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct MemberContact {
    /// Account name: display name, else first and last name, else username
    pub name: String,
    /// Email of the account
    pub email: Option<String>,
    /// Phone number from the profile
    pub phone: Option<String>,
    /// Required fields the member still has to fill in on their account
    pub missing: Vec<String>,
}

/// Account behind the registration a companion was submitted with
#[derive(Serialize, JsonSchema, Debug, Clone, PartialEq)]
pub struct VerifiedInviter {
    /// User ID of the member who submitted the registration
    pub user_id: String,
    /// Name of that account
    pub name: String,
}

/// Guest record with read-only fields resolved at request time
#[derive(Serialize, JsonSchema)]
pub struct EventGuestView {
    #[serde(flatten)]
    guest: EventGuest,
    /// Verified account that invited this guest, for companions only
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_inviter: Option<VerifiedInviter>,
}

#[derive(Serialize, JsonSchema)]
pub struct UserSearchResponse {
    id: String,
    username: String,
    email: String,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct GuestStatusUpdate {
    /// Guest ID
    pub guest_id: String,
    /// Status to set
    pub status: GuestStatus,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct BulkStatusUpdate {
    /// List of guest status updates
    pub updates: Vec<GuestStatusUpdate>,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct BulkMessageData {
    /// List of messages to send
    pub messages: Vec<UserMessage>,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct UserMessage {
    /// User ID to send message to
    pub user_id: String,
    /// Message content
    #[validate(length(min = 1, max = 2000))]
    pub content: Option<String>,
}

#[derive(Validate, Deserialize, JsonSchema)]
pub struct GuestMessageData {
    /// Message content to send
    #[validate(length(min = 1, max = 2000))]
    pub content: String,
    /// Guest statuses to filter by
    pub statuses: Vec<GuestStatus>,
}

/// Add a guest to an event
#[openapi(tag = "Events")]
#[post("/<event_id>/guests", data = "<data>")]
pub async fn add_guest(
    db: &State<Database>,
    user: User,
    event_id: String,
    data: Json<DataCreateGuest>,
) -> Result<Json<GuestResponse>> {
    let data = data.into_inner();

    // Validate the input data
    if let Err(validation_errors) = data.validate() {
        return Err(Error::InvalidRequest {
            code: "validation_error".to_string(),
            errors: validation_errors_to_strings(&validation_errors),
        });
    }
    let guest = EventGuest {
        id: Ulid::new().to_string(),
        event_id: event_id.clone(),
        name: data.name,
        email: data.email,
        phone: data.phone,
        status: GuestStatus::Pending,
        user_id: Some(user.id.clone()),
        plus_one_of: data.plus_one_of.clone(),
        parent_guest_id: data.parent_guest_id,
        is_plus_one: Some(data.plus_one_of.is_some()),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    db.add_guest(&guest).await?;
    Ok(Json(GuestResponse { guest }))
}

/// Update single guest status
#[openapi(tag = "Events")]
#[patch("/<event_id>/guests/<guest_id>/status", data = "<status>")]
pub async fn update_guest_status(
    db: &State<Database>,
    _user: User,
    event_id: String,
    guest_id: String,
    status: Json<GuestStatus>,
) -> Result<Json<()>> {
    db.update_guest_status(&event_id, &guest_id, status.into_inner())
        .await?;
    Ok(Json(()))
}

/// Update multiple guests' status
#[openapi(tag = "Events")]
#[patch("/<event_id>/guests/bulk/status", data = "<data>")]
pub async fn update_bulk_guest_status(
    authifier: &State<Authifier>,
    db: &State<Database>,
    user: User,
    event_id: String,
    data: Json<BulkStatusUpdate>,
) -> Result<Json<()>> {
    // Approving/rejecting requests is the organiser's job (the events portal's
    // pending-requests screen) and DMs the hosts as the caller.
    check_event_organiser(&db.fetch_event(Some(&user.id), &event_id).await?, &user)?;

    let data = data.into_inner();
    let mut approved_guests = Vec::new();
    let mut rejected_guests = Vec::new();

    // First update all guest statuses
    for update in &data.updates {
        db.update_guest_status(&event_id, &update.guest_id, update.status.clone())
            .await?;

        // If the status is Approved or Rejected, add to respective lists for notifications
        if let Ok(guest) = db.get_guest(&event_id, &update.guest_id).await {
            match update.status {
                GuestStatus::Approved => approved_guests.push(guest),
                GuestStatus::Rejected => rejected_guests.push(guest),
                _ => {}
            }
        }
    }

    // Send approval emails to guests who were approved
    if !approved_guests.is_empty() {
        if let EmailVerificationConfig::Enabled { smtp, .. } = &authifier.config.email_verification
        {
            let event = db.fetch_event(None, &event_id).await?;
            let approval_message = format!(
                "This is an automatic system message \n\n
                Your request to attend {}/events/view/{}\n
                We look forward to seeing you there!",
                *APP_URL, event_id
            );

            for guest in &approved_guests {
                smtp.send_email(
                    guest.email.clone(),
                    &Template {
                        title: format!("Approved for {}!", event.title),
                        text: include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/assets/templates/event.txt"
                        ))
                        .into(),
                        url: format!("{}/events/view/{}", *APP_URL, event_id),
                        html: Some(
                            include_str!(concat!(
                                env!("CARGO_MANIFEST_DIR"),
                                "/assets/templates/event.html"
                            ))
                            .into(),
                        ),
                    },
                    json!({
                        "email": guest.email.clone(),
                        "url": format!("{}/events/view/{}", *APP_URL, event_id),
                        "content": format!("{}",
                            approval_message.clone()),
                    }),
                );
            }
        }
    }

    // Send rejection emails to guests who were rejected
    if !rejected_guests.is_empty() {
        if let EmailVerificationConfig::Enabled { smtp, .. } = &authifier.config.email_verification
        {
            let event = db.fetch_event(None, &event_id).await?;
            let rejection_message = format!(
                "This is an automatic system message \n\n
                We regret to inform you that your request to attend {} has been declined. \n
                We appreciate your interest and hope to see you at future events.",
                event.title
            );

            for guest in &rejected_guests {
                smtp.send_email(
                    guest.email.clone(),
                    &Template {
                        title: format!("Update on {} Request", event.title),
                        text: include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/assets/templates/event.txt"
                        ))
                        .into(),
                        url: format!("{}/events/view/{}", *APP_URL, event_id),
                        html: Some(
                            include_str!(concat!(
                                env!("CARGO_MANIFEST_DIR"),
                                "/assets/templates/event.html"
                            ))
                            .into(),
                        ),
                    },
                    json!({
                        "email": guest.email.clone(),
                        "url": format!("{}/events/view/{}", *APP_URL, event_id),
                        "content": format!("<b>This is an automatic system message</b> <br />
                        \n\n{}",
                             rejection_message.clone()),
                    }),
                );
            }
        }
    }

    // Send notification to hosts and event creator
    if !approved_guests.is_empty() || !rejected_guests.is_empty() {
        let event = db.fetch_event(None, &event_id).await?;
        let mut recipients = event.hosts.clone();
        if let Some(creator) = event.created_by {
            recipients.push(creator);
        }

        let status_message = format!(
            "Guest status updates for {}:\n\nApproved: {}\nRejected: {}",
            event.title,
            approved_guests.len(),
            rejected_guests.len()
        );

        for recipient_id in recipients {
            if !may_reach(db, &user, &recipient_id).await {
                continue;
            }

            // Find or create DM channel
            let channel = if let Ok(channel) = db
                .find_direct_message_channel(&user.id, &recipient_id)
                .await
            {
                channel
            } else {
                let new_channel = Channel::DirectMessage {
                    id: Ulid::new().to_string(),
                    active: true,
                    recipients: vec![user.id.clone(), recipient_id.clone()],
                    last_message_id: None,
                    staff_id: None,
                };

                new_channel.create(db).await?;
                new_channel
            };

            // Send the message
            let mut msg = Message {
                id: Ulid::new().to_string(),
                channel: channel.id().to_string(),
                author: user.id.clone(),
                content: Some(status_message.clone()),
                ..Default::default()
            };

            // Create the message with proper notification handling
            msg.create(db, &channel, Some(MessageAuthor::User(&user)))
                .await?;
        }
    }

    Ok(Json(()))
}

/// Get all guests for an event
#[openapi(tag = "Events")]
#[get("/<event_id>/guests")]
pub async fn get_event_guests(
    db: &State<Database>,
    _user: User,
    event_id: String,
) -> Result<Json<Vec<EventGuestView>>> {
    let guests = db.get_event_guests(&event_id).await?;

    // One lookup for every account behind a main contact, rather than one per guest.
    let mut user_ids: Vec<String> = guests
        .iter()
        .filter(|guest| guest.plus_one_of.is_none())
        .filter_map(|guest| guest.user_id.clone())
        .collect();
    user_ids.sort();
    user_ids.dedup();

    let users = if user_ids.is_empty() {
        Vec::new()
    } else {
        db.fetch_users(&user_ids).await?
    };

    let mut inviters = verified_inviters(&guests, &users);
    let guests = guests
        .into_iter()
        .map(|guest| EventGuestView {
            verified_inviter: inviters.remove(&guest.id),
            guest,
        })
        .collect();

    Ok(Json(guests))
}

/// Get the signed-in member's contact details for registering to an event
#[openapi(tag = "Events")]
#[get("/<event_id>/guests/registration-contact", rank = 1)]
pub async fn get_registration_contact(
    authifier: &State<Authifier>,
    user: User,
    event_id: String,
) -> Result<Json<MemberContact>> {
    // The contact is the same for every event; the path only scopes the route.
    let _ = event_id;
    let email = account_email(authifier, &user.id).await;
    Ok(Json(member_contact(&user, email.as_deref())))
}

/// Get a specific guest
#[openapi(tag = "Events")]
#[get("/<event_id>/guests/<guest_id>", rank = 2)]
pub async fn get_guest(
    db: &State<Database>,
    _user: User,
    event_id: String,
    guest_id: String,
) -> Result<Json<EventGuest>> {
    let guest = db.get_guest(&event_id, &guest_id).await?;
    Ok(Json(guest))
}

/// Add multiple guests to an event
#[openapi(tag = "Events")]
#[post("/<event_id>/guests/bulk", data = "<data>")]
pub async fn add_bulk_guests(
    authifier: &State<Authifier>,
    db: &State<Database>,
    user: Option<User>,
    event_id: String,
    data: Json<DataCreateBulkGuests>,
) -> Result<Json<BulkGuestResponse>> {
    let data = data.into_inner();
    let mut created_guests = Vec::new();

    // First create the main contact. A signed-in member is registered as their
    // account, whatever the client sent as main_contact; only an anonymous
    // registration takes the main contact from the request.
    let (name, email, phone) = match &user {
        Some(user) => {
            let account_email = account_email(authifier, &user.id).await;
            let contact = member_contact(user, account_email.as_deref());
            if !contact.missing.is_empty() {
                return Err(Error::InvalidRequest {
                    code: "profile_incomplete".to_string(),
                    errors: contact.missing,
                });
            }
            (
                contact.name,
                contact.email.unwrap_or_default(),
                contact.phone.unwrap_or_default(),
            )
        }
        None => {
            let main_contact = data.main_contact.ok_or_else(|| Error::InvalidRequest {
                code: "validation_error".to_string(),
                errors: vec!["main_contact: required".to_string()],
            })?;
            if let Err(validation_errors) = main_contact.validate() {
                return Err(Error::InvalidRequest {
                    code: "validation_error".to_string(),
                    errors: validation_errors_to_strings(&validation_errors),
                });
            }
            (main_contact.name, main_contact.email, main_contact.phone)
        }
    };

    let main_guest = EventGuest {
        id: Ulid::new().to_string(),
        event_id: event_id.clone(),
        name,
        email,
        phone,
        status: GuestStatus::Pending,
        user_id: user.map(|u| u.id),
        plus_one_of: None,
        parent_guest_id: None,
        is_plus_one: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    db.add_guest(&main_guest).await?;
    created_guests.push(main_guest.clone());

    // Then create additional guests
    for guest_data in data.additional_guests {
        if let Err(validation_errors) = guest_data.validate() {
            return Err(Error::InvalidRequest {
                code: "validation_error".to_string(),
                errors: validation_errors_to_strings(&validation_errors),
            });
        }

        let guest = EventGuest {
            id: Ulid::new().to_string(),
            event_id: event_id.clone(),
            name: guest_data.name,
            email: guest_data.email,
            phone: guest_data.phone,
            status: GuestStatus::Pending,
            user_id: None,
            plus_one_of: Some(main_guest.id.clone()),
            parent_guest_id: guest_data.parent_guest_id,
            is_plus_one: Some(true),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        db.add_guest(&guest).await?;
        created_guests.push(guest);
    }

    // Send welcome emails to all guests
    if let EmailVerificationConfig::Enabled { smtp, .. } = &authifier.config.email_verification {
        let event = db.fetch_event(None, &event_id).await?;
        let welcome_message = format!(
            "Welcome to {}/events/view/{}\n
            You have been added as a guest to this event. \n
            Your approval is pending, we will notify you when it is approved.",
            *APP_URL, event_id
        );

        for guest in &created_guests {
            smtp.send_email(
                guest.email.clone(),
                &Template {
                    title: format!("Welcome to {}!", event.title),
                    text: include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/assets/templates/event.txt"
                    ))
                    .into(),
                    url: format!("{}/events/view/{}", *APP_URL, event_id),
                    html: Some(
                        include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/assets/templates/event.html"
                        ))
                        .into(),
                    ),
                },
                json!({
                    "email": guest.email.clone(),
                    "url": format!("{}/events/view/{}", *APP_URL, event_id),
                    "content": welcome_message.clone(),
                }),
            );
        }

        // Send notification to hosts about new guests
        let mut host_emails = Vec::new();
        for host_id in &event.hosts {
            if let Ok(host) = db.inner().fetch_user(host_id).await {
                if let Ok(account) = authifier.database.find_account(&host.id).await {
                    if let account_host_email = account.email {
                        host_emails.push(account_host_email);
                    }
                }
            }
        }

        if let Some(creator_id) = &event.created_by {
            if let Ok(creator) = db.inner().fetch_user(creator_id).await {
                if let Ok(account) = authifier.database.find_account(&creator.id).await {
                    if let account_creator_email = account.email {
                        host_emails.push(account_creator_email);
                    }
                }
            }
        }

        println!("host_emails: {:?}", host_emails);

        if !host_emails.is_empty() {
            let host_notification = format!(
                "New Guest Registration \n
                {} new guest(s) have registered for your event \n\n
                {}/events/view/{}\n\n
                Please review their registration by clicking \n
                {}/events/pending-requests/{}\n",
                created_guests.len(),
                *APP_URL,
                event_id,
                *APP_URL,
                event_id
            );

            for email in host_emails {
                smtp.send_email(
                    email.clone(),
                    &Template {
                        title: format!("New Guest Registration - {}", event.title),
                        text: include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/assets/templates/event.txt"
                        ))
                        .into(),
                        url: format!("{}/events/view/{}", *APP_URL, event_id),
                        html: Some(
                            include_str!(concat!(
                                env!("CARGO_MANIFEST_DIR"),
                                "/assets/templates/event.html"
                            ))
                            .into(),
                        ),
                    },
                    json!({
                        "email": email.clone(),
                        "url": format!("{}/events/view/{}", *APP_URL, event_id),
                        "content": host_notification.clone(),
                    }),
                );
            }
        }
    }

    Ok(Json(BulkGuestResponse {
        guests: created_guests,
    }))
}

/// Send DM messages to multiple users
#[openapi(tag = "Events")]
#[post("/<event_id>/guests/message", data = "<data>")]
pub async fn send_bulk_messages(
    authifier: &State<Authifier>,
    db: &State<Database>,
    user: User,
    event_id: String,
    data: Json<BulkMessageData>,
) -> Result<Json<()>> {
    let data = data.into_inner();

    // Verify sender is event owner or host
    let event = db.fetch_event(Some(&user.id), &event_id).await?;
    check_event_organiser(&event, &user)?;

    // Get current invited_count or initialize to 0
    let mut invited_count = event.invited_count.unwrap_or(0);

    // Send messages
    for message in data.messages {
        // Invitees are not guests yet, so the recipient can be any member the
        // organiser can see (friend or shared server/DM/group, not blocked).
        let Ok(recipient) = db.fetch_user(&message.user_id).await else {
            continue;
        };
        if !perms(&user).user(&recipient).calc_user(db).await.get_view_profile() {
            continue;
        }

        // Find or create DM channel
        let channel = if let Ok(channel) = db
            .find_direct_message_channel(&user.id, &message.user_id)
            .await
        {
            channel
        } else {
            let new_channel = Channel::DirectMessage {
                id: Ulid::new().to_string(),
                active: true,
                recipients: vec![user.id.clone(), message.user_id.clone()],
                last_message_id: None,
                staff_id: None,
            };

            new_channel.create(db).await?;
            new_channel
        };

        // Send the message
        let mut msg = Message {
            id: Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: user.id.clone(),
            content: Some(format!(
                "{} is inviting you to {} event:\n\n{}/events/view/{}{}",
                user.username,
                event.title,
                *APP_URL,
                event_id,
                message.content.as_ref().map(|c| format!("\n\n{}", c)).unwrap_or_default()
            )),
            ..Default::default()
        };

        // Create the message with proper notification handling
        msg.create(db, &channel, Some(MessageAuthor::User(&user)))
            .await?;

        // Update channel as active if it wasn't already
        if let Channel::DirectMessage { active, .. } = &channel {
            if !active {
                db.update_channel(
                    &channel.id(),
                    &PartialChannel {
                        active: Some(true),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?;
            }
        }

        // Send email notification
        if let EmailVerificationConfig::Enabled { smtp, .. } = &authifier.config.email_verification
        {
            if let Ok(recipient) = db.inner().fetch_user(&message.user_id).await {
                if let Ok(account) = authifier.database.find_account(&recipient.id).await {
                    let email = account.email.clone();
                    smtp.send_email(
                        email,
                        &Template {
                            title: format!("New message from {} - {}", user.username, event.title),
                            text: include_str!(concat!(
                                env!("CARGO_MANIFEST_DIR"),
                                "/assets/templates/event.txt"
                            ))
                            .into(),
                            url: format!("{}/events/view/{}", *APP_URL, event_id),
                            html: Some(
                                include_str!(concat!(
                                    env!("CARGO_MANIFEST_DIR"),
                                    "/assets/templates/event.html"
                                ))
                                .into(),
                            ),
                        },
                        json!({
                            "email": account.email.clone(),
                            "url": format!("{}/events/view/{}", *APP_URL, event_id),
                            "content": format!(
                                "{} is inviting you to {} event:\n\n{}/events/view/{}{}\n\n", 
                                user.username, 
                                event.title, 
                                *APP_URL, 
                                event_id,
                                message.content.as_ref().map(|c| format!("\n\n{}", c)).unwrap_or_default()
                            ),
                        }),
                    );
                }
            }
        }

        // Increment the counter for each guest invited
        invited_count += 1;
    }

    // Update the event with the new invited_count
    db.update_event(
        &event_id,
        &PartialEvent {
            invited_count: Some(invited_count),
            ..Default::default()
        },
    )
    .await?;

    Ok(Json(()))
}

/// Send messages to guests filtered by status
#[openapi(tag = "Events")]
#[post("/<event_id>/guests/notify", data = "<data>")]
pub async fn notify_guests(
    authifier: &State<Authifier>,
    db: &State<Database>,
    user: User,
    event_id: String,
    data: Json<GuestMessageData>,
) -> Result<Json<()>> {
    let data = data.into_inner();

    // Verify sender is event owner or host
    let event = db.fetch_event(Some(&user.id), &event_id).await?;
    check_event_organiser(&event, &user)?;

    // Get all guests for this event with matching statuses
    let guests = db.get_event_guests(&event_id).await?;
    let filtered_guests: Vec<&EventGuest> = guests
        .iter()
        .filter(|g| data.statuses.contains(&g.status.clone()))
        .collect();

    // Process each guest
    for guest in filtered_guests {
        if let Some(user_id) = &guest.user_id {
            if !may_reach(db, &user, user_id).await {
                continue;
            }

            // Find or create DM channel and send message
            let channel =
                if let Ok(channel) = db.find_direct_message_channel(&user.id, user_id).await {
                    channel
                } else {
                    let new_channel = Channel::DirectMessage {
                        id: Ulid::new().to_string(),
                        active: false,
                        recipients: vec![user.id.clone(), user_id.clone()],
                        last_message_id: None,
                        staff_id: None,
                    };

                    new_channel.create(db).await?;
                    new_channel
                };

            // Send DM
            let msg = Message {
                id: Ulid::new().to_string(),
                channel: channel.id().to_string(),
                author: user.id.clone(),
                content: Some(format!(
                    "{} is inviting you to this event: {}/events/view/{}",
                    user.username, *APP_URL, event_id
                )),
                ..Default::default()
            };

            db.insert_message(&msg).await?;
        }
        if let EmailVerificationConfig::Enabled {
            templates,
            expiry,
            smtp,
        } = &authifier.config.email_verification
        {
            smtp.send_email(
                guest.email.clone(),
                &Template {
                    title: format!("Notification from event - {}", event.title),
                    text: include_str!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/assets/templates/event.txt"
                    ))
                    .into(),
                    url: format!("{}/events/view/{}", *APP_URL, event_id),
                    html: Some(
                        include_str!(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/assets/templates/event.html"
                        ))
                        .into(),
                    ),
                },
                json!({
                    "email": guest.email.clone(),
                    "url": format!("{}/events/view/{}", *APP_URL, event_id),
                    "title": event.title.clone(),
                    "content": data.content.clone(),
                }),
            );
        }
    }

    Ok(Json(()))
}

/// Email of the account behind a user, if the account can be found
async fn account_email(authifier: &Authifier, user_id: &str) -> Option<String> {
    authifier
        .database
        .find_account(user_id)
        .await
        .ok()
        .map(|account| account.email)
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Name an account goes by: display name, else first and last name, else username
fn account_name(user: &User) -> String {
    if let Some(display_name) = non_empty(user.display_name.as_deref()) {
        return display_name;
    }

    let profile = user.profile.as_ref();
    let full_name = vec![
        profile.and_then(|p| non_empty(p.first_name.as_deref())),
        profile.and_then(|p| non_empty(p.last_name.as_deref())),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<String>>()
    .join(" ");

    if full_name.is_empty() {
        user.username.clone()
    } else {
        full_name
    }
}

/// Contact details a member's registration records, all from internal sources:
/// the name and phone from the user, the email from their Authifier account.
fn member_contact(user: &User, account_email: Option<&str>) -> MemberContact {
    let email = non_empty(account_email);
    let phone = non_empty(
        user.profile
            .as_ref()
            .and_then(|p| p.phone_number.as_deref()),
    );

    let mut missing = Vec::new();
    if email.is_none() {
        missing.push("email".to_string());
    }
    if phone.is_none() {
        missing.push("phone".to_string());
    }

    MemberContact {
        name: account_name(user),
        email,
        phone,
        missing,
    }
}

/// Verified inviter of each companion, keyed by the companion's guest ID.
///
/// Follows companion → plus_one_of → main contact → user_id, and only when
/// every link holds: the main contact is in this event's list and is not a
/// companion itself, it was registered by a signed-in account that still
/// exists, and the companion does not carry a different account of its own.
/// Anything else is left unverified rather than guessed.
fn verified_inviters(guests: &[EventGuest], users: &[User]) -> HashMap<String, VerifiedInviter> {
    let guests_by_id: HashMap<&str, &EventGuest> =
        guests.iter().map(|guest| (guest.id.as_str(), guest)).collect();
    let users_by_id: HashMap<&str, &User> =
        users.iter().map(|user| (user.id.as_str(), user)).collect();

    guests
        .iter()
        .filter_map(|guest| {
            let main_id = guest.plus_one_of.as_deref()?;
            if main_id == guest.id {
                return None;
            }

            let main = guests_by_id.get(main_id)?;
            if main.plus_one_of.is_some() || main.event_id != guest.event_id {
                return None;
            }

            let inviter_id = main.user_id.as_deref()?;
            if guest.user_id.as_deref().is_some_and(|id| id != inviter_id) {
                return None;
            }

            let inviter = users_by_id.get(inviter_id)?;
            Some((
                guest.id.clone(),
                VerifiedInviter {
                    user_id: inviter.id.clone(),
                    name: account_name(inviter),
                },
            ))
        })
        .collect()
}

// Helper function to convert validation errors to strings
/// Guard for the event tools that DM people as the caller: only the event's
/// creator or a host may use them, and never while restricted.
fn check_event_organiser(event: &Event, user: &User) -> Result<()> {
    if user.is_restricted_actor() {
        Error::from_user_permission(UserPermission::SendMessage)
    } else if event.created_by.as_deref() != Some(&user.id) && !event.hosts.contains(&user.id) {
        Err(Error::NotFound)
    } else {
        Ok(())
    }
}

/// Whether an event tool may DM `recipient_id` as `sender`: restricted members
/// are shadowed from everyone but staff.
async fn may_reach(db: &Database, sender: &User, recipient_id: &str) -> bool {
    match db.fetch_user(recipient_id).await {
        Ok(recipient) => recipient.is_visible_to(sender),
        Err(_) => false,
    }
}

fn validation_errors_to_strings(errors: &validator::ValidationErrors) -> Vec<String> {
    errors
        .field_errors()
        .iter()
        .map(|(field, errors)| {
            format!(
                "{}: {}",
                field,
                errors.first().unwrap().message.clone().unwrap_or_default()
            )
        })
        .collect()
}

#[cfg(test)]
mod organiser_tests {
    use revolt_quark::models::user::Flags;

    use super::*;

    fn event() -> Event {
        Event {
            created_by: Some("creator".into()),
            hosts: vec!["host".into()],
            ..Default::default()
        }
    }

    fn user(id: &str, flags: Option<i32>) -> User {
        User {
            id: id.into(),
            flags,
            ..Default::default()
        }
    }

    #[test]
    fn only_unrestricted_creator_or_host_may_message_as_organiser() {
        let event = event();
        assert!(check_event_organiser(&event, &user("creator", None)).is_ok());
        assert!(check_event_organiser(&event, &user("host", None)).is_ok());
        assert!(matches!(
            check_event_organiser(&event, &user("stranger", None)),
            Err(Error::NotFound)
        ));
        assert!(matches!(
            check_event_organiser(&event, &user("host", Some(Flags::Restricted as i32))),
            Err(Error::MissingUserPermission { .. })
        ));
    }

    #[async_std::test]
    async fn invitations_skip_restricted_members_unless_sent_by_staff() {
        let db = revolt_quark::DatabaseInfo::Dummy.connect().await.unwrap();
        let restricted = user("target", Some(Flags::Restricted as i32));
        let host = user("host", None);
        let staff = User {
            privileged: true,
            ..user("staff", None)
        };

        assert!(perms(&host).user(&user("target", None)).calc_user(&db).await.get_view_profile());
        assert!(!perms(&host).user(&restricted).calc_user(&db).await.get_view_profile());
        assert!(perms(&staff).user(&restricted).calc_user(&db).await.get_view_profile());
    }
}

#[cfg(test)]
mod tests {
    use revolt_quark::models::user::UserProfile;

    use super::*;

    fn user(id: &str, username: &str) -> User {
        User {
            id: id.to_string(),
            username: username.to_string(),
            ..Default::default()
        }
    }

    fn with_profile(mut user: User, first: Option<&str>, last: Option<&str>, phone: Option<&str>) -> User {
        user.profile = Some(UserProfile {
            first_name: first.map(str::to_string),
            last_name: last.map(str::to_string),
            phone_number: phone.map(str::to_string),
            ..Default::default()
        });
        user
    }

    fn guest(id: &str, user_id: Option<&str>, plus_one_of: Option<&str>) -> EventGuest {
        EventGuest {
            id: id.to_string(),
            event_id: "event".to_string(),
            parent_guest_id: None,
            plus_one_of: plus_one_of.map(str::to_string),
            user_id: user_id.map(str::to_string),
            name: format!("{id} name"),
            email: format!("{id}@guest.test"),
            phone: format!("+503 {id}"),
            status: GuestStatus::Pending,
            is_plus_one: plus_one_of.map(|_| true),
            created_at: "2026-10-05T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn name_prefers_display_name() {
        let mut member = with_profile(user("u", "ana_p"), Some("Ana"), Some("Pérez"), None);
        member.display_name = Some("  Anita  ".to_string());
        assert_eq!(account_name(&member), "Anita");
    }

    #[test]
    fn name_falls_back_to_first_and_last_name() {
        let mut member = with_profile(user("u", "ana_p"), Some(" Ana "), Some("Pérez"), None);
        member.display_name = Some("   ".to_string());
        assert_eq!(account_name(&member), "Ana Pérez");
    }

    #[test]
    fn name_uses_whichever_part_of_the_full_name_exists() {
        let first_only = with_profile(user("u", "ana_p"), Some("Ana"), Some(""), None);
        let last_only = with_profile(user("u", "ana_p"), None, Some("Pérez"), None);
        assert_eq!(account_name(&first_only), "Ana");
        assert_eq!(account_name(&last_only), "Pérez");
    }

    #[test]
    fn name_falls_back_to_username() {
        assert_eq!(account_name(&user("u", "ana_p")), "ana_p");
        let blank = with_profile(user("u", "ana_p"), Some(" "), None, None);
        assert_eq!(account_name(&blank), "ana_p");
    }

    #[test]
    fn member_contact_takes_email_from_account_and_phone_from_profile() {
        let member = with_profile(user("u", "ana_p"), Some("Ana"), Some("Pérez"), Some(" +503 7000 0000 "));
        let contact = member_contact(&member, Some(" ana@kimani.test "));
        assert_eq!(
            contact,
            MemberContact {
                name: "Ana Pérez".to_string(),
                email: Some("ana@kimani.test".to_string()),
                phone: Some("+503 7000 0000".to_string()),
                missing: vec![],
            }
        );
    }

    #[test]
    fn member_contact_reports_missing_email_and_phone() {
        let no_profile = member_contact(&user("u", "ana_p"), None);
        assert_eq!(no_profile.missing, vec!["email", "phone"]);
        assert_eq!(no_profile.email, None);
        assert_eq!(no_profile.phone, None);

        let blank = with_profile(user("u", "ana_p"), None, None, Some("  "));
        assert_eq!(member_contact(&blank, Some("")).missing, vec!["email", "phone"]);

        let no_phone = member_contact(&user("u", "ana_p"), Some("ana@kimani.test"));
        assert_eq!(no_phone.missing, vec!["phone"]);
    }

    #[test]
    fn companion_of_a_member_registration_gets_the_verified_inviter() {
        let mut member = user("member", "ana_p");
        member.display_name = Some("Ana Pérez".to_string());
        let guests = vec![
            guest("main", Some("member"), None),
            guest("plus1", None, Some("main")),
            guest("plus2", None, Some("main")),
        ];

        let inviters = verified_inviters(&guests, &[member]);

        let expected = VerifiedInviter {
            user_id: "member".to_string(),
            name: "Ana Pérez".to_string(),
        };
        assert_eq!(inviters.get("plus1"), Some(&expected));
        assert_eq!(inviters.get("plus2"), Some(&expected));
        // The main contact is the member; it has no inviter.
        assert_eq!(inviters.get("main"), None);
        assert_eq!(inviters.len(), 2);
    }

    #[test]
    fn companion_of_an_anonymous_registration_is_not_verified() {
        let guests = vec![guest("main", None, None), guest("plus1", None, Some("main"))];
        assert!(verified_inviters(&guests, &[]).is_empty());
    }

    #[test]
    fn broken_links_are_not_verified() {
        let member = user("member", "ana_p");
        let mut other_event_main = guest("other_main", Some("member"), None);
        other_event_main.event_id = "other".to_string();

        let guests = vec![
            // Main contact not in this list.
            guest("orphan", None, Some("missing")),
            // Points at itself.
            guest("self", Some("member"), Some("self")),
            // Main contact is itself a companion.
            guest("main", Some("member"), None),
            guest("nested_main", Some("member"), Some("main")),
            guest("nested", None, Some("nested_main")),
            // Main contact belongs to another event.
            other_event_main,
            guest("cross_event", None, Some("other_main")),
        ];

        let inviters = verified_inviters(&guests, &[member]);

        for id in ["orphan", "self", "nested", "cross_event"] {
            assert_eq!(inviters.get(id), None, "{id} should not be verified");
        }
        // The direct companion of a real main contact still is.
        assert!(inviters.contains_key("nested_main"));
    }

    #[test]
    fn companion_carrying_a_different_account_is_not_verified() {
        let guests = vec![
            guest("main", Some("member"), None),
            guest("spoofed", Some("someone_else"), Some("main")),
            guest("same_account", Some("member"), Some("main")),
        ];

        let inviters = verified_inviters(&guests, &[user("member", "ana_p")]);

        assert_eq!(inviters.get("spoofed"), None);
        assert!(inviters.contains_key("same_account"));
    }

    #[test]
    fn deleted_account_is_not_verified() {
        let guests = vec![
            guest("main", Some("gone"), None),
            guest("plus1", None, Some("main")),
        ];
        assert!(verified_inviters(&guests, &[]).is_empty());
    }

    #[test]
    fn guest_view_keeps_guest_and_inviter_details_apart() {
        let guests = vec![
            guest("main", Some("member"), None),
            guest("plus1", None, Some("main")),
        ];
        let mut inviters = verified_inviters(&guests, &[user("member", "ana_p")]);
        let views: Vec<EventGuestView> = guests
            .into_iter()
            .map(|guest| EventGuestView {
                verified_inviter: inviters.remove(&guest.id),
                guest,
            })
            .collect();

        let json = serde_json::to_value(&views).unwrap();

        // The companion keeps its own contact details, flattened as before.
        assert_eq!(json[1]["_id"], "plus1");
        assert_eq!(json[1]["email"], "plus1@guest.test");
        assert_eq!(json[1]["phone"], "+503 plus1");
        assert_eq!(json[1]["plus_one_of"], "main");
        // The inviter carries only the account's ID and name, never contact details.
        assert_eq!(
            json[1]["verified_inviter"],
            serde_json::json!({ "user_id": "member", "name": "ana_p" })
        );
        // Records without a verified inviter don't gain the field at all.
        assert!(json[0].get("verified_inviter").is_none());
    }

    #[test]
    fn bulk_request_accepts_a_missing_main_contact() {
        let data: DataCreateBulkGuests =
            serde_json::from_str(r#"{ "additional_guests": [] }"#).unwrap();
        assert!(data.main_contact.is_none());

        let data: DataCreateBulkGuests = serde_json::from_str(
            r#"{ "main_contact": { "name": "A B", "email": "a@b.co", "phone": "1" }, "additional_guests": [] }"#,
        )
        .unwrap();
        assert!(data.main_contact.is_some());
    }
}
