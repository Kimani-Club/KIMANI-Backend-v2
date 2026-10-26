use revolt_quark::authifier::config::{EmailVerificationConfig, Template};
use revolt_quark::authifier::Authifier;
use revolt_quark::{
    models::channels::channel::{Channel, PartialChannel},
    models::channels::message::Message,
    models::events::event::PartialEvent,
    models::events::guest::{EventGuest, GuestStatus},
    models::user::User,
    types::push::MessageAuthor,
    variables::delta::APP_URL,
    Database, Error, Result,
};
use rocket::{serde::json::Json, State};
use serde::{Deserialize, Serialize};
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
    /// Main contact guest
    pub main_contact: DataCreateGuest,
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
    _user: User,
    event_id: String,
    data: Json<BulkStatusUpdate>,
) -> Result<Json<()>> {
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
            // Find or create DM channel
            let channel = if let Ok(channel) = db
                .find_direct_message_channel(&_user.id, &recipient_id)
                .await
            {
                channel
            } else {
                let new_channel = Channel::DirectMessage {
                    id: Ulid::new().to_string(),
                    active: true,
                    recipients: vec![_user.id.clone(), recipient_id.clone()],
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
                author: _user.id.clone(),
                content: Some(status_message.clone()),
                ..Default::default()
            };

            // Create the message with proper notification handling
            msg.create(db, &channel, Some(MessageAuthor::User(&_user)))
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
) -> Result<Json<Vec<EventGuest>>> {
    let guests = db.get_event_guests(&event_id).await?;
    Ok(Json(guests))
}

/// Get a specific guest
#[openapi(tag = "Events")]
#[get("/<event_id>/guests/<guest_id>")]
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

    // First create the main contact
    if let Err(validation_errors) = data.main_contact.validate() {
        return Err(Error::InvalidRequest {
            code: "validation_error".to_string(),
            errors: validation_errors_to_strings(&validation_errors),
        });
    }

    let main_guest = EventGuest {
        id: Ulid::new().to_string(),
        event_id: event_id.clone(),
        name: data.main_contact.name,
        email: data.main_contact.email,
        phone: data.main_contact.phone,
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
    if event.created_by.as_deref() != Some(&user.id) && !event.hosts.contains(&user.id) {
        return Err(Error::NotFound);
    }

    // Get current invited_count or initialize to 0
    let mut invited_count = event.invited_count.unwrap_or(0);

    // Send messages
    for message in data.messages {
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
    if event.created_by.as_deref() != Some(&user.id) && !event.hosts.contains(&user.id) {
        return Err(Error::NotFound);
    }

    // Get all guests for this event with matching statuses
    let guests = db.get_event_guests(&event_id).await?;
    let filtered_guests: Vec<&EventGuest> = guests
        .iter()
        .filter(|g| data.statuses.contains(&g.status.clone()))
        .collect();

    // Process each guest
    for guest in filtered_guests {
        if let Some(user_id) = &guest.user_id {
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

// Helper function to convert validation errors to strings
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
