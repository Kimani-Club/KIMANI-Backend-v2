use crate::{
    models::{user::RelationshipStatus, User},
    permissions::PermissionCalculator,
    UserPermission, UserPermissions, UserPerms,
};

impl PermissionCalculator<'_> {
    /// Calculate the permissions from our perspective to the given user
    ///
    /// How the permission is calculated:
    /// 1. Are we the target?
    ///     - If so: return maximum permissions
    /// 2. Do we have a relationship with the target?
    ///     - If we are friends: return maximum permissions
    ///     - If either user blocked each other: return only `Access`
    ///     - If incoming / outgoing request: add `Access` to the list
    /// 3. Determine whether there is a mutual connection:
    ///     1. Check if the "mutual connection" flag is set.
    ///     2. Check if we share any servers with the target.
    ///     3. Check if we share any DMs or groups with the target.
    /// 4. Do we have a mutual connection with the target?
    ///     - If so: return `Access` + `ViewProfile`
    /// 5. Return no permissions
    pub async fn calc_user(&mut self, db: &crate::Database) -> UserPerms {
        if self.user.has() {
            let v = calculate_permission(self, db).await;
            self.cached_user_permission = Some(v);
            UserPermissions([v])
        } else {
            panic!("Expected `PermissionCalculator.user` to exist.")
        }
    }
}

/// Find the relationship between two users
pub fn get_relationship(a: &User, b: &str) -> RelationshipStatus {
    if a.id == b {
        return RelationshipStatus::User;
    }

    if let Some(relations) = &a.relations {
        if let Some(relationship) = relations.iter().find(|x| x.id == b) {
            return relationship.status.clone();
        }
    }

    RelationshipStatus::None
}

/// Find the note `a` holds against their own relationship entry for `b`
///
/// This only ever reads `a`'s own `relations` array (never `b`'s), so it can
/// only surface a note to the recipient of an Incoming request.
pub fn get_relationship_note(a: &User, b: &str) -> Option<String> {
    a.relations
        .as_ref()?
        .iter()
        .find(|x| x.id == b && x.status == RelationshipStatus::Incoming)?
        .note
        .clone()
}

/// Internal helper function for calculating permission
async fn calculate_permission(data: &mut PermissionCalculator<'_>, db: &crate::Database) -> u32 {
    let user = data.user.get().unwrap();

    if data.perspective.privileged {
        return u32::MAX;
    }

    if data.perspective.id == user.id {
        return u32::MAX;
    }

    // Restricted members are shadowed: other members cannot find, view or contact them.
    if user.is_restricted() {
        return 0;
    }

    let permissions = calculate_relationship_permission(data, db).await;

    // A restricted member may not start conversations or invite anyone; their
    // only writable channel is a staff DM, which bypasses user permissions.
    if data.perspective.is_restricted() {
        permissions & !(UserPermission::SendMessage as u32 | UserPermission::Invite as u32)
    } else {
        permissions
    }
}

/// Permission granted by the relationship / mutual connection between two users
async fn calculate_relationship_permission(
    data: &mut PermissionCalculator<'_>,
    db: &crate::Database,
) -> u32 {
    let user = data.user.get().unwrap();

    let relationship = data.flag_known_relationship.cloned().unwrap_or_else(|| {
        user.relationship
            .as_ref()
            .cloned()
            .unwrap_or_else(|| get_relationship(data.perspective, &user.id))
    });

    let mut permissions: u32 = 0;
    match relationship {
        RelationshipStatus::Friend => return u32::MAX,
        RelationshipStatus::Blocked | RelationshipStatus::BlockedOther => {
            return UserPermission::Access as u32
        }
        RelationshipStatus::Incoming | RelationshipStatus::Outgoing => {
            permissions = UserPermission::Access as u32;
        }
        _ => {}
    }

    // ! FIXME: add boolean switch for permission for users to globally message a user
    // maybe an enum?
    // PrivacyLevel { Private, Friends, Mutual, Public, Global }

    // ! FIXME: add boolean switch for permission for users to mutually DM a user

    if data.flag_has_mutual_connection
        || data
            .perspective
            .has_mutual_connection(db, &user.id)
            .await
            .unwrap_or(false)
    {
        permissions = UserPermission::Access + UserPermission::ViewProfile;

        if user.bot.is_some() || data.perspective.bot.is_some() {
            permissions += UserPermission::SendMessage as u32;
        }

        return permissions;
    }

    permissions
}

#[cfg(test)]
mod restricted_tests {
    use crate::models::user::{Flags, Relationship, RelationshipStatus};
    use crate::{perms, UserPermission};

    use super::*;

    fn user(id: &str) -> User {
        User {
            id: id.into(),
            ..Default::default()
        }
    }

    fn restricted(id: &str) -> User {
        User {
            flags: Some(Flags::Restricted as i32),
            ..user(id)
        }
    }

    fn friend_of(mut user: User, other: &str) -> User {
        user.relations = Some(vec![Relationship {
            id: other.into(),
            status: RelationshipStatus::Friend,
            note: None,
        }]);
        user
    }

    #[async_std::test]
    async fn restricted_target_is_invisible_to_members_and_visible_to_staff() {
        let db = crate::DatabaseInfo::Dummy.connect().await.unwrap();
        let target = restricted("target");

        let member = friend_of(user("member"), "target");
        assert_eq!(perms(&member).user(&target).calc_user(&db).await.0[0], 0);
        assert!(!target.is_visible_to(&member));

        let staff = User {
            privileged: true,
            ..user("staff")
        };
        assert_eq!(perms(&staff).user(&target).calc_user(&db).await.0[0], u32::MAX);
        assert!(target.is_visible_to(&staff));

        assert_eq!(perms(&target).user(&target).calc_user(&db).await.0[0], u32::MAX);
        assert!(target.is_visible_to(&target));
    }

    #[async_std::test]
    async fn restricted_perspective_cannot_message_or_invite() {
        let db = crate::DatabaseInfo::Dummy.connect().await.unwrap();
        let friend = user("friend");
        let me = friend_of(restricted("me"), "friend");

        let permissions = perms(&me).user(&friend).calc_user(&db).await;
        assert!(!permissions.get_send_message());
        assert_eq!(permissions.0[0] & UserPermission::Invite as u32, 0);
        assert_ne!(permissions.0[0] & UserPermission::Access as u32, 0);
    }
}
