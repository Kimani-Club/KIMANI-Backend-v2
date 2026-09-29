use crate::events::client::EventV1;
use crate::models::user::{
    Badges, FieldsUser, PartialUser, Presence, RelationshipStatus, User, UserHint,
};
use crate::permissions::defn::UserPerms;
use crate::permissions::r#impl::user::{get_relationship, get_relationship_note};
use crate::{perms, Database, Error, Result};

use futures::try_join;
use impl_ops::impl_op_ex_commutative;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use revolt_database::RatelimitEventType;
use revolt_presence::filter_online;
use std::collections::HashSet;
use std::ops;
use std::time::Duration;

impl_op_ex_commutative!(+ |a: &i32, b: &Badges| -> i32 { *a | *b as i32 });

impl User {
    /// Update user data
    pub async fn update<'a>(
        &mut self,
        db: &Database,
        partial: PartialUser,
        remove: Vec<FieldsUser>,
    ) -> Result<()> {
        for field in &remove {
            self.remove(field);
        }

        self.apply_options(partial.clone());

        db.update_user(&self.id, &partial, remove.clone()).await?;

        EventV1::UserUpdate {
            id: self.id.clone(),
            data: partial,
            clear: remove,
            event_id: Some(ulid::Ulid::new().to_string()),
        }
        .p_user(self.id.clone(), db)
        .await;

        Ok(())
    }

    /// Remove a field from User object
    pub fn remove(&mut self, field: &FieldsUser) {
        match field {
            FieldsUser::Avatar => self.avatar = None,
            FieldsUser::StatusText => {
                if let Some(x) = self.status.as_mut() {
                    x.text = None;
                }
            }
            FieldsUser::StatusPresence => {
                if let Some(x) = self.status.as_mut() {
                    x.presence = None;
                }
            }
            FieldsUser::ProfileContent => {
                if let Some(x) = self.profile.as_mut() {
                    x.content = None;
                }
            }
            FieldsUser::ProfileBackground => {
                if let Some(x) = self.profile.as_mut() {
                    x.background = None;
                }
            }
            FieldsUser::DisplayName => self.display_name = None,
            FieldsUser::TemporaryPassword => self.temporary_password = None,
        }
    }

    /// Mutate the user object to remove redundant information
    #[must_use]
    pub fn foreign(mut self) -> User {
        self.profile = None;
        self.relations = None;
        self.relationship_note = None;

        let mut badges = self.badges.unwrap_or(0);
        if let Ok(id) = ulid::Ulid::from_string(&self.id) {
            // Yes, this is hard-coded
            // No, I don't care + ratio
            if id.datetime().timestamp_millis() < 1629638578431 {
                badges = badges + Badges::EarlyAdopter;
            }
        }

        self.badges = Some(badges);

        if let Some(status) = &self.status {
            if let Some(presence) = &status.presence {
                if presence == &Presence::Invisible {
                    self.status = None;
                    self.online = Some(false);
                }
            }
        }

        self
    }

    /// Fetch foreign users by a list of IDs
    pub async fn fetch_foreign_users(db: &Database, user_ids: &[String]) -> Result<Vec<User>> {
        let online_ids = filter_online(user_ids).await;

        Ok(db
            .fetch_users(user_ids)
            .await?
            .into_iter()
            .map(|mut user| {
                user.online = Some(online_ids.contains(&user.id));
                user.foreign()
            })
            .collect::<Vec<User>>())
    }

    /// Mutate the user object to include relationship (if it does not already exist)
    #[must_use]
    pub fn with_relationship(self, perspective: &User) -> User {
        let mut user = self.foreign();

        if user.relationship.is_none() {
            user.relationship = Some(get_relationship(perspective, &user.id));
        }

        user.relationship_note = if user.relationship == Some(RelationshipStatus::Incoming) {
            get_relationship_note(perspective, &user.id)
        } else {
            None
        };

        user
    }

    /// Mutate user object with given permission
    #[must_use]
    pub fn apply_permission(mut self, permission: &UserPerms) -> User {
        if !permission.get_view_profile() {
            self.status = None;
        }

        self
    }

    /// Helper function to apply relationship and permission
    #[must_use]
    pub fn with_perspective(self, perspective: &User, permission: &UserPerms) -> User {
        self.with_relationship(perspective)
            .apply_permission(permission)
    }

    /// Helper function to calculate perspective
    pub async fn with_auto_perspective(self, db: &Database, perspective: &User) -> User {
        let user = self.with_relationship(perspective);
        let permissions = perms(perspective).user(&user).calc_user(db).await;
        user.apply_permission(&permissions)
    }

    /// Check whether two users have a mutual connection
    ///
    /// This will check if user and user_b share a server or a group.
    pub async fn has_mutual_connection(&self, db: &Database, user_b: &str) -> Result<bool> {
        Ok(!db
            .fetch_mutual_server_ids(&self.id, user_b)
            .await?
            .is_empty()
            || !db
                .fetch_mutual_channel_ids(&self.id, user_b)
                .await?
                .is_empty())
    }

    /// Check if this user can acquire another server
    pub async fn can_acquire_server(&self, db: &Database) -> Result<bool> {
        // ! FIXME: hardcoded max server count
        Ok(db.fetch_server_count(&self.id).await? <= 100)
    }

    /// Sanitise and validate a username can be used
    pub fn validate_username(username: String) -> Result<String> {
        // Copy the username for validation
        let username_lowercase = username.to_lowercase();

        // Block homoglyphs
        if decancer::cure(&username_lowercase).into_str() != username_lowercase {
            return Err(Error::InvalidUsername);
        }

        // Ensure the username itself isn't blocked
        const BLOCKED_USERNAMES: &[&str] = &["admin", "revolt"];

        for username in BLOCKED_USERNAMES {
            if username_lowercase == *username {
                return Err(Error::InvalidUsername);
            }
        }

        // Ensure none of the following substrings show up in the username
        const BLOCKED_SUBSTRINGS: &[&str] = &["```"];

        for substr in BLOCKED_SUBSTRINGS {
            if username_lowercase.contains(substr) {
                return Err(Error::InvalidUsername);
            }
        }

        Ok(username)
    }

    // Find a free discriminator for a given username
    pub async fn find_discriminator(
        db: &Database,
        username: &str,
        preferred: Option<(String, String)>,
    ) -> Result<String> {
        let search_space: &HashSet<String> = &DISCRIMINATOR_SEARCH_SPACE_QUARK;
        let used_discriminators: HashSet<String> = db
            .fetch_discriminators_in_use(username)
            .await?
            .into_iter()
            .collect();

        let available_discriminators: Vec<&String> =
            search_space.difference(&used_discriminators).collect();

        if available_discriminators.is_empty() {
            return Err(Error::UsernameTaken);
        }

        if let Some((preferred, target_id)) = preferred {
            if available_discriminators.contains(&&preferred) {
                return Ok(preferred);
            } else {
                let rvdb: revolt_database::Database = db.clone().into();
                if rvdb
                    .has_ratelimited(
                        &target_id,
                        RatelimitEventType::DiscriminatorChange,
                        Duration::from_secs(60 * 60 * 24),
                        1,
                    )
                    .await
                    .map_err(Error::from_core)?
                {
                    return Err(Error::DiscriminatorChangeRatelimited);
                }

                rvdb.insert_ratelimit_event(&revolt_database::RatelimitEvent {
                    id: ulid::Ulid::new().to_string(),
                    target_id,
                    event_type: RatelimitEventType::DiscriminatorChange,
                })
                .await
                .map_err(Error::from_core)?;
            }
        }

        let mut rng = rand::thread_rng();
        Ok(available_discriminators
            .choose(&mut rng)
            .expect("we can assert this has an element")
            .to_string())
    }

    /// Update a user's username
    pub async fn update_username(&mut self, db: &Database, username: String) -> Result<()> {
        let username = User::validate_username(username)?;
        if self.username.to_lowercase() == username.to_lowercase() {
            self.update(
                db,
                PartialUser {
                    username: Some(username),
                    ..Default::default()
                },
                vec![],
            )
            .await
        } else {
            self.update(
                db,
                PartialUser {
                    discriminator: Some(
                        User::find_discriminator(
                            db,
                            &username,
                            Some((self.discriminator.to_string(), self.id.clone())),
                        )
                        .await?,
                    ),
                    username: Some(username),
                    ..Default::default()
                },
                vec![],
            )
            .await
        }
    }

    /// Build the existing private event payload from the new state, not stale relations.
    fn relationship_payload(self, status: RelationshipStatus, note: Option<String>) -> Self {
        let mut user = self.foreign();
        user.relationship_note = if status == RelationshipStatus::Incoming {
            note
        } else {
            None
        };
        user.relationship = Some(status);
        user
    }

    /// Apply a certain relationship between two users
    pub async fn apply_relationship(
        &self,
        db: &Database,
        target: &mut User,
        local: RelationshipStatus,
        remote: RelationshipStatus,
        note: Option<String>,
    ) -> Result<()> {
        // The note (if any) belongs solely to the recipient's own `Incoming`
        // entry — never mirrored onto the sender's `Outgoing` entry below.
        if let Err(e) = db
            .set_relationship(&self.id, &target.id, &local, None)
            .await
        {
            return Err(Error::DatabaseError {
                operation: "update_one",
                with: "user",
            });
        }

        // Await second operation
        if let Err(e) = db
            .set_relationship(&target.id, &self.id, &remote, note.as_deref())
            .await
        {
            return Err(Error::DatabaseError {
                operation: "update_one",
                with: "user",
            });
        }

        EventV1::UserRelationship {
            id: target.id.clone(),
            user: self.clone().relationship_payload(remote.clone(), note),
            status: remote,
        }
        .private(target.id.clone())
        .await;

        EventV1::UserRelationship {
            id: self.id.clone(),
            user: target.clone().relationship_payload(local.clone(), None),
            status: local.clone(),
        }
        .private(self.id.clone())
        .await;

        target.relationship.replace(local);
        target.relationship_note = None;
        Ok(())
    }

    /// Add another user as a friend
    ///
    /// `note` is an optional message attached by the sender, shown to the
    /// recipient alongside their incoming request. It is only meaningful
    /// (and only ever persisted) on a fresh `None -> Outgoing/Incoming`
    /// request; accepting an existing `Incoming` request carries no note of
    /// its own here since one was already stored when the request arrived.
    pub async fn add_friend(
        &self,
        db: &Database,
        target: &mut User,
        note: Option<String>,
    ) -> Result<()> {
        match get_relationship(self, &target.id) {
            RelationshipStatus::User => Err(Error::NoEffect),
            RelationshipStatus::Friend => Err(Error::AlreadyFriends),
            RelationshipStatus::Outgoing => Err(Error::AlreadySentRequest),
            RelationshipStatus::Blocked => Err(Error::Blocked),
            RelationshipStatus::BlockedOther => Err(Error::BlockedByOther),
            RelationshipStatus::Incoming => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Friend,
                    RelationshipStatus::Friend,
                    None,
                )
                .await
            }
            RelationshipStatus::None => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Outgoing,
                    RelationshipStatus::Incoming,
                    note,
                )
                .await
            }
        }
    }

    /// Remove another user as a friend
    pub async fn remove_friend(&self, db: &Database, target: &mut User) -> Result<()> {
        match get_relationship(self, &target.id) {
            RelationshipStatus::Friend
            | RelationshipStatus::Outgoing
            | RelationshipStatus::Incoming => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::None,
                    RelationshipStatus::None,
                    None,
                )
                .await
            }
            _ => Err(Error::NoEffect),
        }
    }

    /// Block another user
    pub async fn block_user(&self, db: &Database, target: &mut User) -> Result<()> {
        match get_relationship(self, &target.id) {
            RelationshipStatus::User | RelationshipStatus::Blocked => Err(Error::NoEffect),
            RelationshipStatus::BlockedOther => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Blocked,
                    RelationshipStatus::Blocked,
                    None,
                )
                .await
            }
            RelationshipStatus::None
            | RelationshipStatus::Friend
            | RelationshipStatus::Incoming
            | RelationshipStatus::Outgoing => {
                self.apply_relationship(
                    db,
                    target,
                    RelationshipStatus::Blocked,
                    RelationshipStatus::BlockedOther,
                    None,
                )
                .await
            }
        }
    }

    /// Unblock another user
    pub async fn unblock_user(&self, db: &Database, target: &mut User) -> Result<()> {
        match get_relationship(self, &target.id) {
            RelationshipStatus::Blocked => match get_relationship(target, &self.id) {
                RelationshipStatus::Blocked => {
                    self.apply_relationship(
                        db,
                        target,
                        RelationshipStatus::BlockedOther,
                        RelationshipStatus::Blocked,
                        None,
                    )
                    .await
                }
                RelationshipStatus::BlockedOther => {
                    self.apply_relationship(
                        db,
                        target,
                        RelationshipStatus::None,
                        RelationshipStatus::None,
                        None,
                    )
                    .await
                }
                _ => Err(Error::InternalError),
            },
            _ => Err(Error::NoEffect),
        }
    }

    /// Check whether this user has another user blocked
    pub fn has_blocked(&self, user: &str) -> bool {
        matches!(
            get_relationship(self, user),
            RelationshipStatus::Blocked | RelationshipStatus::BlockedOther
        )
    }

    /// Mark as deleted
    pub async fn mark_deleted(&mut self, db: &Database) -> Result<()> {
        self.update(
            db,
            PartialUser {
                username: Some(format!("Deleted User {}", self.id)),
                flags: Some(2),
                ..Default::default()
            },
            vec![
                FieldsUser::Avatar,
                FieldsUser::StatusText,
                FieldsUser::StatusPresence,
                FieldsUser::ProfileContent,
                FieldsUser::ProfileBackground,
                FieldsUser::TemporaryPassword,
            ],
        )
        .await
    }

    /// Find a user from a given token and hint
    #[async_recursion]
    pub async fn from_token(db: &Database, token: &str, hint: UserHint) -> Result<User> {
        match hint {
            UserHint::Bot => db.fetch_user(&db.fetch_bot_by_token(token).await?.id).await,
            UserHint::User => db.fetch_user_by_token(token).await,
            UserHint::Any => {
                if let Ok(user) = User::from_token(db, token, UserHint::User).await {
                    Ok(user)
                } else {
                    User::from_token(db, token, UserHint::Bot).await
                }
            }
        }
    }
}

pub static DISCRIMINATOR_SEARCH_SPACE_QUARK: Lazy<HashSet<String>> = Lazy::new(|| {
    let mut set = (2..9999)
        .map(|v| format!("{:0>4}", v))
        .collect::<HashSet<String>>();

    for discrim in [
        123, 1234, 1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 9999,
    ] {
        set.remove(&format!("{:0>4}", discrim));
    }

    set.into_iter().collect()
});

#[cfg(test)]
mod friend_request_tests {
    use super::*;
    use crate::models::user::Relationship;
    use serde_json::{json, to_value};

    fn user(id: &str) -> User {
        User {
            id: id.into(),
            ..Default::default()
        }
    }

    #[async_std::test]
    async fn note_does_not_grant_send_message() {
        let db = crate::DatabaseInfo::Dummy.connect().await.unwrap();
        let sender = user("sender");
        for status in [
            RelationshipStatus::Incoming,
            RelationshipStatus::Outgoing,
            RelationshipStatus::Friend,
            RelationshipStatus::Blocked,
        ] {
            let mut recipient = user("recipient");
            for note in [None, Some("private note".into())] {
                recipient.relations = Some(vec![Relationship {
                    id: sender.id.clone(),
                    status: status.clone(),
                    note,
                }]);
                let permission = crate::perms(&recipient).user(&sender).calc_user(&db).await;
                assert_eq!(
                    permission.get_send_message(),
                    status == RelationshipStatus::Friend
                );
            }
        }
        assert_eq!(crate::UserPermission::SendMessage as u32, 4);
    }

    /// Run against an isolated MongoDB and Redis, never a production database.
    #[async_std::test]
    #[ignore = "requires FRIEND_NOTE_TEST_MONGODB and isolated REDIS_URI"]
    async fn friend_request_mongo_transitions() {
        let uri = std::env::var("FRIEND_NOTE_TEST_MONGODB").expect("isolated test MongoDB URI");
        let db = crate::DatabaseInfo::MongoDb(uri).connect().await.unwrap();
        for action in [
            "accept",
            "reject",
            "cancel",
            "block_recipient",
            "block_sender",
            "without_note",
        ] {
            let sender_id = ulid::Ulid::new().to_string();
            let recipient_id = ulid::Ulid::new().to_string();
            let sender = user(&sender_id);
            let mut recipient = user(&recipient_id);
            db.insert_user(&sender).await.unwrap();
            db.insert_user(&recipient).await.unwrap();
            let note = if action == "without_note" {
                None
            } else {
                Some("$literal note".into())
            };
            sender
                .add_friend(&db, &mut recipient, note.clone())
                .await
                .unwrap();
            let mut sender = db.fetch_user(&sender_id).await.unwrap();
            let mut recipient = db.fetch_user(&recipient_id).await.unwrap();
            assert_eq!(
                get_relationship(&sender, &recipient_id),
                RelationshipStatus::Outgoing
            );
            assert_eq!(
                get_relationship(&recipient, &sender_id),
                RelationshipStatus::Incoming
            );
            assert_eq!(get_relationship_note(&recipient, &sender_id), note);
            assert!(get_relationship_note(&sender, &recipient_id).is_none());
            assert!(sender.relations.as_ref().unwrap()[0].note.is_none());
            match action {
                "accept" => recipient.add_friend(&db, &mut sender, None).await.unwrap(),
                "reject" => recipient.remove_friend(&db, &mut sender).await.unwrap(),
                "cancel" => sender.remove_friend(&db, &mut recipient).await.unwrap(),
                "block_recipient" => recipient.block_user(&db, &mut sender).await.unwrap(),
                "block_sender" => sender.block_user(&db, &mut recipient).await.unwrap(),
                _ => (),
            }
            let sender = db.fetch_user(&sender_id).await.unwrap();
            let recipient = db.fetch_user(&recipient_id).await.unwrap();
            if action == "accept" {
                assert_eq!(
                    get_relationship(&sender, &recipient_id),
                    RelationshipStatus::Friend
                );
                assert_eq!(
                    get_relationship(&recipient, &sender_id),
                    RelationshipStatus::Friend
                );
            }
            for user in [&sender, &recipient] {
                assert!(user
                    .relations
                    .as_ref()
                    .map_or(true, |rs| rs.iter().all(|r| r.note.is_none())));
            }
            db.delete_user(&sender_id).await.unwrap();
            db.delete_user(&recipient_id).await.unwrap();
        }
    }

    #[test]
    fn recipient_only_and_foreign_privacy() {
        let sender = user("sender");
        let mut recipient = user("recipient");
        recipient.relations = Some(vec![Relationship {
            id: sender.id.clone(),
            status: RelationshipStatus::Incoming,
            note: Some("private note".into()),
        }]);
        assert_eq!(
            sender
                .clone()
                .with_relationship(&recipient)
                .relationship_note
                .as_deref(),
            Some("private note")
        );
        assert!(recipient
            .clone()
            .with_relationship(&sender)
            .relationship_note
            .is_none());
        // HTTP accept response holds the new status but its viewer still has the old relation.
        let accepted = sender
            .clone()
            .relationship_payload(RelationshipStatus::Friend, None);
        assert!(accepted
            .with_relationship(&recipient)
            .relationship_note
            .is_none());
        assert!(sender
            .clone()
            .with_relationship(&user("third"))
            .relationship_note
            .is_none());
        for status in [
            RelationshipStatus::Outgoing,
            RelationshipStatus::Friend,
            RelationshipStatus::None,
            RelationshipStatus::Blocked,
            RelationshipStatus::BlockedOther,
        ] {
            recipient.relations.as_mut().unwrap()[0].status = status;
            assert!(sender
                .clone()
                .with_relationship(&recipient)
                .relationship_note
                .is_none());
        }
        let mut stale = sender;
        stale.relationship_note = Some("stale".into());
        assert!(stale.foreign().relationship_note.is_none());
    }

    #[test]
    fn existing_event_payload_uses_new_status_and_clears_note() {
        for (id, status, note) in [
            (
                "recipient",
                RelationshipStatus::Incoming,
                Some("private note".to_string()),
            ),
            ("sender", RelationshipStatus::Outgoing, None),
            ("recipient", RelationshipStatus::Friend, None),
            ("recipient", RelationshipStatus::None, None),
            ("sender", RelationshipStatus::None, None),
            ("recipient", RelationshipStatus::Blocked, None),
            ("sender", RelationshipStatus::BlockedOther, None),
        ] {
            let payload = user("other").relationship_payload(status.clone(), note.clone());
            let event = to_value(EventV1::UserRelationship {
                id: id.into(),
                user: payload,
                status: status.clone(),
            })
            .unwrap();
            assert_eq!(event["type"], json!("UserRelationship"));
            assert_eq!(event["id"], json!(id));
            assert_eq!(event["status"], to_value(status).unwrap());
            assert_eq!(event["user"]["relationship"], event["status"]);
            assert_eq!(
                event["user"].get("relationship_note").cloned(),
                note.map(|note| json!(note))
            );
            assert!(event["user"].get("relations").is_none());
        }
    }

    #[test]
    fn persisted_schema_roundtrip_preserves_note_across_models() {
        let document = json!({"_id":"sender","status":"Incoming","note":"private note"});
        let old: Relationship = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(to_value(old).unwrap(), document);
        let core: revolt_database::Relationship = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(to_value(&core).unwrap(), document);
        let api: revolt_models::v0::Relationship = core.into();
        assert_eq!(to_value(api).unwrap(), document);
        let legacy: Relationship =
            serde_json::from_value(json!({"_id":"sender","status":"Incoming"})).unwrap();
        assert!(legacy.note.is_none());
        assert!(to_value(legacy).unwrap().get("note").is_none());
    }
}
