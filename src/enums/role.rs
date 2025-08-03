use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_role", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Admin,
    SuperAdmin,
    Police,
}

impl Role {

    pub fn all() -> Vec<Role> {
        vec![Role::User, Role::Admin, Role::SuperAdmin, Role::Police]
    }


    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::SuperAdmin)
    }


    pub fn has_admin_privileges(&self) -> bool {
        matches!(self, Role::Admin | Role::SuperAdmin)
    }

    pub fn has_police_privileges(&self) -> bool {
        matches!(self, Role::Police | Role::Admin | Role::SuperAdmin)
    }

    pub fn can_access_security_alerts(&self) -> bool {
        matches!(self, Role::Police | Role::Admin | Role::SuperAdmin)
    }


    pub fn can_create_security_alerts(&self) -> bool {
        !matches!(self, Role::User) // All except regular users
    }

    pub fn can_modify_role(&self, target_role: &Role) -> bool {
        match self {
            Role::SuperAdmin => true,
            Role::Admin => matches!(target_role, Role::User),
            _ => false,
        }
    }


    pub fn hierarchy_level(&self) -> u8 {
        match self {
            Role::User => 1,
            Role::Police => 2,
            Role::Admin => 3,
            Role::SuperAdmin => 4,
        }
    }


    pub fn has_higher_or_equal_privileges(&self, other: &Role) -> bool {
        self.hierarchy_level() >= other.hierarchy_level()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Admin => write!(f, "admin"),
            Role::SuperAdmin => write!(f, "super_admin"),
            Role::Police => write!(f, "police"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(Role::User),
            "admin" => Ok(Role::Admin),
            "super_admin" | "superadmin" => Ok(Role::SuperAdmin),
            "police" => Ok(Role::Police),
            _ => Err(format!("Invalid role: {}. Valid roles are: user, admin, super_admin, police", s)),
        }
    }
}

impl From<Role> for String {
    fn from(role: Role) -> Self {
        role.to_string()
    }
}
