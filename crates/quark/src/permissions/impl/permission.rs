use std::collections::HashSet;

use crate::{
    get_relationship,
    models::{user::RelationshipStatus, Channel}, permissions::PermissionCalculator, Override, Permission, PermissionValue,
    Permissions, Perms, Result, ALLOW_IN_TIMEOUT, DEFAULT_PERMISSION_DIRECT_MESSAGE, DEFAULT_PERMISSION_MARKETPLACE_DM,
    DEFAULT_PERMISSION_SAVED_MESSAGES, DEFAULT_PERMISSION_VIEW_ONLY,
};

use super::super::Permission::GrantAllSafe;

impl PermissionCalculator<'_> {
    /// Calculate the permissions from our perspective to the given server or channel
    ///
    /// Refer to https://developers.revolt.chat/stack/delta/permissions#flow-chart for more information
    pub async fn calc(&mut self, db: &crate::Database) -> Result<Perms> {
        if self.perspective.privileged {
            return Ok(Permissions([GrantAllSafe as u64]));
        }

        let mut value = if self.channel.has() {
            calculate_channel_permission(self, db).await?
        } else if self.server.has() {
            calculate_server_permission(self, db).await?
        } else {
            panic!("Expected `PermissionCalculator.(user|server) to exist.");
        };

        // A restricted (frozen) member keeps read access but can no longer post,
        // react, upload, invite or join voice anywhere — except their saved notes
        // and a staff DM opened to them, which is how admins and the member talk.
        let exempt = self.channel.get().map_or(false, |channel| {
            matches!(channel, Channel::SavedMessages { .. })
                || is_member_side_of_staff_dm(channel, &self.perspective.id)
        });

        if self.perspective.is_restricted() && !exempt {
            value.restrict(*DEFAULT_PERMISSION_VIEW_ONLY);
        }

        let value = value.into();

        self.cached_permission = Some(value);
        Ok(Permissions([value]))
    }
}

/// Whether `user_id` is the member (non-staff) recipient of a staff DM
fn is_member_side_of_staff_dm(channel: &Channel, user_id: &str) -> bool {
    matches!(channel, Channel::DirectMessage { recipients, .. } if recipients.iter().any(|r| r == user_id))
        && channel.staff_id().map_or(false, |staff| staff != user_id)
}

/// Internal helper function for calculating server permission
async fn calculate_server_permission(
    data: &mut PermissionCalculator<'_>,
    db: &crate::Database,
) -> Result<PermissionValue> {
    let server = data.server.get().unwrap();

    // 1. Check if owner.
    if data.perspective.id == server.owner {
        return Ok((Permission::GrantAllSafe as u64).into());
    }

    // 2. Fetch member.
    if !data.member.has() {
        data.member
            .set(db.fetch_member(&server.id, &data.perspective.id).await?);
    }

    let member = data.member.get().expect("Member should be present by now.");

    // 3. Apply allows from default_permissions.
    let mut permissions: PermissionValue = server.default_permissions.into();

    // 4. Resolve each role in order.
    let member_roles: HashSet<&String> = member.roles.iter().collect();

    if !member_roles.is_empty() {
        let mut roles = server
            .roles
            .iter()
            .filter(|(id, _)| member_roles.contains(id))
            .map(|(_, role)| {
                let v: Override = role.permissions.into();
                (role.rank, v)
            })
            .collect::<Vec<(i64, Override)>>();

        roles.sort_by(|a, b| b.0.cmp(&a.0));

        // 5. Apply allows and denies from roles.
        for (_, v) in roles {
            permissions.apply(v);
        }
    }

    // 5. Revoke permissions if member is timed out.
    if member.in_timeout() {
        permissions.restrict(*ALLOW_IN_TIMEOUT);
    }

    Ok(permissions)
}

/// Internal helper function for calculating channel permission
async fn calculate_channel_permission(
    data: &mut PermissionCalculator<'_>,
    db: &crate::Database,
) -> Result<PermissionValue> {
    // Pre-calculate server permissions if applicable.
    // We do this to satisfy the borrow checker.
    let server_id = match data.channel.get().unwrap() {
        Channel::TextChannel { server, .. } | Channel::VoiceChannel { server, .. } => Some(server),
        _ => None,
    };

    let mut permissions = if let Some(server) = server_id {
        if !data.server.has() {
            data.server.set(db.fetch_server(server).await?);
        }

        calculate_server_permission(data, db).await?
    } else {
        0_u64.into()
    };

    // Borrow the channel now and continue as normal.
    let channel = data.channel.get().unwrap();

    // 1. Check channel type.
    let value: PermissionValue = match channel {
        Channel::SavedMessages { user, .. } => {
            if user == &data.perspective.id {
                DEFAULT_PERMISSION_SAVED_MESSAGES.into()
            } else {
                0_u64.into()
            }
        }
        Channel::DirectMessage { recipients, .. } => {
            // 2. Ensure we are a recipient.
            if !recipients.contains(&data.perspective.id) {
                0_u64.into()
            } else {
                // 3. Fetch user.
                let other_user = recipients
                    .iter()
                    .find(|x| x != &&data.perspective.id)
                    .unwrap();

                let blocked = matches!(
                    get_relationship(data.perspective, other_user),
                    RelationshipStatus::Blocked | RelationshipStatus::BlockedOther
                );

                // A DM opened by staff stays writable for the member (no friendship
                // needed, even while restricted) unless one side blocked the other.
                // The staff side only writes while currently privileged, which
                // returns early in `calc`; otherwise the normal rules below apply.
                if !blocked && is_member_side_of_staff_dm(channel, &data.perspective.id) {
                    return Ok((*DEFAULT_PERMISSION_DIRECT_MESSAGE).into());
                }

                let user = db.fetch_user(other_user).await?;
                data.user.set(user);

                // 4. Calculate user permissions.
                let perms = data.calc_user(db).await;

                // 5. Check if the user can send messages.
                if perms.get_send_message() {
                    (*DEFAULT_PERMISSION_DIRECT_MESSAGE).into()
                } else {
                    (*DEFAULT_PERMISSION_VIEW_ONLY).into()
                }
            }
        }
        Channel::Group {
            owner,
            permissions,
            recipients,
            ..
        } => {
            // 2. Check if user is owner.
            if &data.perspective.id == owner {
                (Permission::GrantAllSafe as u64).into()
            } else {
                // 3. Check that we are actually in the group.
                if recipients.contains(&data.perspective.id) {
                    // 4. Pull out group permissions.
                    permissions
                        .map(|x| x as u64)
                        .unwrap_or(*DEFAULT_PERMISSION_DIRECT_MESSAGE)
                        .into()
                } else {
                    0_u64.into()
                }
            }
        }
        Channel::TextChannel {
            default_permissions,
            role_permissions,
            ..
        }
        | Channel::VoiceChannel {
            default_permissions,
            role_permissions,
            ..
        } => {
            // 2. If server owner, just grant all permissions.
            //
            // Member may be present and we need to check or
            // we can just grant all if member is not present.
            //
            // In the case member isn't present, the previous
            // step did not fetch member as we are the server owner.
            if let Some(member) = data.member.get() {
                let server = data.server.get().unwrap();
                if server.owner == member.id.user {
                    return Ok((Permission::GrantAllSafe as u64).into());
                }

                // 3. Apply default allows and denies for channel.
                if let Some(default) = default_permissions {
                    permissions.apply((*default).into());
                }

                // 4. Resolve each role in order.
                let member_roles: HashSet<&String> = member.roles.iter().collect();

                if !member_roles.is_empty() {
                    let mut roles = role_permissions
                        .iter()
                        .filter(|(id, _)| member_roles.contains(id))
                        .filter_map(|(id, permission)| {
                            server.roles.get(id).map(|role| {
                                let v: Override = (*permission).into();
                                (role.rank, v)
                            })
                        })
                        .collect::<Vec<(i64, Override)>>();

                    roles.sort_by(|a, b| b.0.cmp(&a.0));

                    // 5. Apply allows and denies from roles.
                    for (_, v) in roles {
                        permissions.apply(v);
                    }
                }

                // 5. Revoke permissions if member is timed out.
                if member.in_timeout() {
                    permissions.restrict(*ALLOW_IN_TIMEOUT);
                }

                permissions
            } else {
                (Permission::GrantAllSafe as u64).into()
            }
        }
        Channel::MarketplaceDM { buyer, seller, .. } => {
            if buyer == &data.perspective.id || seller == &data.perspective.id {
                (*DEFAULT_PERMISSION_MARKETPLACE_DM).into()
            } else {
                0_u64.into()
            }
        }

        Channel::ExperienceDM { user, host, .. } => {
            if user == &data.perspective.id || host == &data.perspective.id {
                (*DEFAULT_PERMISSION_DIRECT_MESSAGE).into()
            } else {
                0_u64.into()
            }
        }

        Channel::AdminDM { admin, user, .. } => {
            if admin == &data.perspective.id || user == &data.perspective.id {
                (*DEFAULT_PERMISSION_DIRECT_MESSAGE).into()
            } else {
                0_u64.into()
            }
        }
    };

    Ok(value)
}

#[cfg(test)]
mod restricted_tests {
    use crate::{
        models::{
            user::{Flags, Relationship, RelationshipStatus},
            Channel, User,
        },
        perms, Permission, DEFAULT_PERMISSION_DIRECT_MESSAGE, DEFAULT_PERMISSION_VIEW_ONLY,
    };

    fn user(id: &str, restricted: bool) -> User {
        User {
            id: id.into(),
            flags: restricted.then(|| Flags::Restricted as i32),
            ..Default::default()
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

    fn dm(staff_id: Option<&str>) -> Channel {
        Channel::DirectMessage {
            id: "dm".into(),
            active: true,
            recipients: vec!["admin".into(), "member".into()],
            last_message_id: None,
            staff_id: staff_id.map(Into::into),
        }
    }

    async fn channel_permission(perspective: &User, channel: &Channel) -> u64 {
        let db = crate::DatabaseInfo::Dummy.connect().await.unwrap();
        perms(perspective).channel(channel).calc(&db).await.unwrap().0[0]
    }

    #[async_std::test]
    async fn restricted_member_is_view_only_in_server_channel() {
        let channel = Channel::TextChannel {
            id: "channel".into(),
            server: "server".into(),
            name: "general".into(),
            description: None,
            icon: None,
            banner: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: Default::default(),
            nsfw: false,
            hide_title: false,
            password: None,
        };

        let active = channel_permission(&user("member", false), &channel).await;
        assert_ne!(active & Permission::SendMessage as u64, 0);

        let restricted = channel_permission(&user("member", true), &channel).await;
        assert_eq!(restricted, *DEFAULT_PERMISSION_VIEW_ONLY);
    }

    fn blocking(mut user: User, other: &str, status: RelationshipStatus) -> User {
        user.relations = Some(vec![Relationship {
            id: other.into(),
            status,
            note: None,
        }]);
        user
    }

    #[async_std::test]
    async fn member_can_always_reply_in_a_staff_dm_even_when_restricted() {
        let channel = dm(Some("admin"));
        for member in [user("member", false), user("member", true)] {
            assert_eq!(
                channel_permission(&member, &channel).await,
                *DEFAULT_PERMISSION_DIRECT_MESSAGE
            );
        }

        let staff = User {
            privileged: true,
            ..user("admin", false)
        };
        assert_ne!(
            channel_permission(&staff, &channel).await & Permission::SendMessage as u64,
            0
        );
    }

    #[async_std::test]
    async fn former_staff_falls_back_to_normal_dm_rules() {
        // No longer privileged and not a friend: the staff mark grants nothing.
        assert_eq!(
            channel_permission(&user("admin", false), &dm(Some("admin"))).await,
            *DEFAULT_PERMISSION_VIEW_ONLY
        );
    }

    #[async_std::test]
    async fn staff_dm_honours_blocks() {
        let channel = dm(Some("admin"));
        for status in [RelationshipStatus::Blocked, RelationshipStatus::BlockedOther] {
            let member = blocking(user("member", false), "admin", status);
            assert_eq!(
                channel_permission(&member, &channel).await,
                *DEFAULT_PERMISSION_VIEW_ONLY
            );
        }
    }

    #[async_std::test]
    async fn saved_messages_stay_writable_when_restricted() {
        let channel = Channel::SavedMessages {
            id: "notes".into(),
            user: "member".into(),
        };
        assert_ne!(
            channel_permission(&user("member", true), &channel).await & Permission::SendMessage as u64,
            0
        );
    }

    #[async_std::test]
    async fn plain_dm_is_view_only_for_a_restricted_member() {
        let channel = dm(None);
        assert_eq!(
            channel_permission(&friend_of(user("member", false), "admin"), &channel).await,
            *DEFAULT_PERMISSION_DIRECT_MESSAGE
        );
        assert_eq!(
            channel_permission(&friend_of(user("member", true), "admin"), &channel).await,
            *DEFAULT_PERMISSION_VIEW_ONLY
        );
    }
}
