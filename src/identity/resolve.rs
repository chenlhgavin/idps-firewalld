//! Identity resolution helpers.

use crate::identity::model::{AppIdentity, IdentityType};
use crate::identity::procfs::program_from_cmdline;
use crate::identity::provider::AndroidPackageMap;

/// Resolve a stable app identity from rule-facing fields.
#[must_use]
pub fn resolve_identity(pkg: Option<&str>, program: Option<&str>, uid: Option<u32>) -> AppIdentity {
    match (
        pkg.filter(|value| !value.is_empty()),
        program.filter(|value| !value.is_empty()),
    ) {
        (Some(pkg), _) => AppIdentity {
            app_id: format!("pkg:{pkg}"),
            identity_type: IdentityType::App,
            package: Some(pkg.to_string()),
            app_name: None,
            program: program.map(str::to_string),
            uid,
        },
        (None, Some(program)) => AppIdentity {
            app_id: format!("prog:{program}"),
            identity_type: IdentityType::Program,
            package: None,
            app_name: None,
            program: Some(program.to_string()),
            uid,
        },
        (None, None) => uid.map_or_else(
            || AppIdentity {
                app_id: "unknown".to_string(),
                identity_type: IdentityType::Unknown,
                package: None,
                app_name: None,
                program: None,
                uid: None,
            },
            |uid| AppIdentity {
                app_id: format!("uid:{uid}"),
                identity_type: IdentityType::Uid,
                package: None,
                app_name: None,
                program: None,
                uid: Some(uid),
            },
        ),
    }
}

/// Resolve the best stable identity for an observed task or flow.
#[must_use]
pub fn resolve_observed_identity(
    packages: Option<&AndroidPackageMap>,
    program: Option<&str>,
    uid: Option<u32>,
) -> AppIdentity {
    if let Some(uid) = uid
        && let Some(package) = packages.and_then(|packages| packages.unique_package_for_uid(uid))
    {
        return resolve_identity(Some(package), program, Some(uid));
    }

    resolve_identity(None, program, uid)
}

/// Resolve the best stable identity for an observed process, optionally using
/// a richer command-line string.
#[must_use]
pub fn resolve_observed_process_identity(
    packages: Option<&AndroidPackageMap>,
    cmdline: Option<&str>,
    program: Option<&str>,
    uid: Option<u32>,
) -> AppIdentity {
    let cmdline_program = cmdline.and_then(program_from_cmdline);
    let mut identity =
        resolve_observed_identity(packages, cmdline_program.as_deref().or(program), uid);
    if identity.identity_type != IdentityType::App
        && let Some(cmdline) = cmdline.filter(|value| !value.trim().is_empty())
    {
        identity.app_name = Some(cmdline.to_string());
    }
    identity
}

/// Rebuild one identity struct from its stable app-id string.
#[must_use]
pub fn identity_from_app_id(app_id: &str, packages: Option<&AndroidPackageMap>) -> AppIdentity {
    if let Some(package) = app_id.strip_prefix("pkg:") {
        return AppIdentity {
            app_id: app_id.to_string(),
            identity_type: IdentityType::App,
            package: Some(package.to_string()),
            app_name: None,
            program: None,
            uid: packages.and_then(|packages| packages.unique_uid_for_package(package)),
        };
    }

    if let Some(program) = app_id.strip_prefix("prog:") {
        return AppIdentity {
            app_id: app_id.to_string(),
            identity_type: IdentityType::Program,
            package: None,
            app_name: None,
            program: Some(program.to_string()),
            uid: None,
        };
    }

    if let Some(uid) = app_id
        .strip_prefix("uid:")
        .and_then(|value| value.parse::<u32>().ok())
    {
        return AppIdentity {
            app_id: app_id.to_string(),
            identity_type: IdentityType::Uid,
            package: None,
            app_name: None,
            program: None,
            uid: Some(uid),
        };
    }

    AppIdentity {
        app_id: app_id.to_string(),
        identity_type: IdentityType::Unknown,
        package: None,
        app_name: None,
        program: None,
        uid: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::model::IdentityType;
    use crate::identity::provider::AndroidPackageMap;

    use super::{
        identity_from_app_id, resolve_identity, resolve_observed_identity,
        resolve_observed_process_identity,
    };

    #[test]
    fn prefers_package_identity() {
        let identity = resolve_identity(Some("com.demo.browser"), Some("browserd"), Some(1000));
        assert_eq!(identity.identity_type, IdentityType::App);
        assert_eq!(identity.app_id, "pkg:com.demo.browser");
    }

    #[test]
    fn falls_back_to_program_identity() {
        let identity = resolve_identity(None, Some("netd"), None);
        assert_eq!(identity.identity_type, IdentityType::Program);
        assert_eq!(identity.app_id, "prog:netd");
    }

    #[test]
    fn falls_back_to_unknown_identity() {
        let identity = resolve_identity(None, None, Some(1000));
        assert_eq!(identity.identity_type, IdentityType::Uid);
        assert_eq!(identity.app_id, "uid:1000");
        assert_eq!(identity.uid, Some(1000));
    }

    #[test]
    fn resolves_observed_uid_to_package_when_android_mapping_exists() {
        let packages = AndroidPackageMap::parse_packages_list(
            "com.demo.browser 10123 0 /data/user/0/com.demo.browser default\n",
        )
        .expect("package list parsed");

        let identity = resolve_observed_identity(Some(&packages), Some("browserd"), Some(10123));
        assert_eq!(identity.identity_type, IdentityType::App);
        assert_eq!(identity.app_id, "pkg:com.demo.browser");
        assert_eq!(identity.uid, Some(10123));
    }

    #[test]
    fn rebuilds_uid_identity_from_app_id() {
        let identity = identity_from_app_id("uid:10123", None);
        assert_eq!(identity.identity_type, IdentityType::Uid);
        assert_eq!(identity.uid, Some(10123));
    }

    #[test]
    fn resolves_process_identity_from_cmdline() {
        let identity =
            resolve_observed_process_identity(None, Some("/system/bin/netd --flag"), None, None);
        assert_eq!(identity.identity_type, IdentityType::Program);
        assert_eq!(identity.app_id, "prog:netd");
        assert_eq!(
            identity.app_name.as_deref(),
            Some("/system/bin/netd --flag")
        );
    }
}
