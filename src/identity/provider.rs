//! Android package to UID identity sources.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Parsed Android package registry derived from `packages.list`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AndroidPackageMap {
    package_to_uids: BTreeMap<String, Vec<u32>>,
    uid_to_packages: BTreeMap<u32, Vec<String>>,
}

impl AndroidPackageMap {
    /// Parse one Android `packages.list` payload.
    ///
    /// Every valid line must start with `<package> <uid> ...`; trailing columns
    /// are ignored because they vary across Android releases.
    pub fn parse_packages_list(payload: &str) -> Result<Self> {
        let mut package_to_uids: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
        let mut uid_to_packages: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();

        for (line_no, raw_line) in payload.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut fields = line.split_whitespace();
            let Some(package) = fields.next() else {
                continue;
            };
            let Some(uid_field) = fields.next() else {
                continue;
            };
            let uid = uid_field.parse::<u32>().with_context(|| {
                format!(
                    "invalid Android package uid '{uid_field}' on line {}",
                    line_no + 1
                )
            })?;

            package_to_uids
                .entry(package.to_string())
                .or_default()
                .insert(uid);
            uid_to_packages
                .entry(uid)
                .or_default()
                .insert(package.to_string());
        }

        Ok(Self {
            package_to_uids: package_to_uids
                .into_iter()
                .map(|(package, uids)| (package, uids.into_iter().collect()))
                .collect(),
            uid_to_packages: uid_to_packages
                .into_iter()
                .map(|(uid, packages)| (uid, packages.into_iter().collect()))
                .collect(),
        })
    }

    /// Load the Android package registry from disk.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let payload = fs::read_to_string(path)
            .with_context(|| format!("failed to read Android package list {}", path.display()))?;
        Self::parse_packages_list(&payload)
    }

    /// Load the Android package registry when the file exists.
    pub fn load_if_present(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        Self::load_from_path(path).map(Some)
    }

    /// Return the resolved UIDs for one package.
    #[must_use]
    pub fn uids_for_package(&self, package: &str) -> Option<&[u32]> {
        self.package_to_uids.get(package).map(Vec::as_slice)
    }

    /// Return the single resolved UID for one package, if it is unique.
    #[must_use]
    pub fn unique_uid_for_package(&self, package: &str) -> Option<u32> {
        let uids = self.uids_for_package(package)?;
        (uids.len() == 1).then_some(uids[0])
    }

    /// Return the packages currently bound to one UID.
    #[must_use]
    pub fn packages_for_uid(&self, uid: u32) -> Option<&[String]> {
        self.uid_to_packages.get(&uid).map(Vec::as_slice)
    }

    /// Return the single package currently bound to one UID, if it is unique.
    #[must_use]
    pub fn unique_package_for_uid(&self, uid: u32) -> Option<&str> {
        let packages = self.packages_for_uid(uid)?;
        (packages.len() == 1).then_some(packages[0].as_str())
    }

    /// Return whether the map currently has no parsed package rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.package_to_uids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::AndroidPackageMap;

    #[test]
    fn parses_packages_list_payload() {
        let packages = AndroidPackageMap::parse_packages_list(
            "\
com.demo.browser 10123 0 /data/user/0/com.demo.browser default
com.demo.media 10124 0 /data/user/0/com.demo.media default
",
        )
        .expect("package list parsed");

        assert_eq!(
            packages.unique_uid_for_package("com.demo.browser"),
            Some(10123)
        );
        assert_eq!(
            packages.unique_package_for_uid(10124),
            Some("com.demo.media")
        );
    }

    #[test]
    fn keeps_shared_uid_packages_ambiguous() {
        let packages = AndroidPackageMap::parse_packages_list(
            "\
com.demo.a 10123 0 /data/user/0/com.demo.a default
com.demo.b 10123 0 /data/user/0/com.demo.b default
",
        )
        .expect("package list parsed");

        assert_eq!(packages.unique_package_for_uid(10123), None);
        assert_eq!(packages.packages_for_uid(10123).expect("packages").len(), 2);
    }

    #[test]
    fn loads_packages_list_from_disk_when_present() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("packages.list");
        fs::write(
            &path,
            "com.demo.browser 10123 0 /data/user/0/com.demo.browser default\n",
        )
        .expect("fixture written");

        let packages = AndroidPackageMap::load_if_present(&path)
            .expect("load succeeded")
            .expect("package map present");
        assert_eq!(
            packages.unique_uid_for_package("com.demo.browser"),
            Some(10123)
        );
    }

    #[test]
    fn returns_none_when_package_file_is_missing() {
        let tempdir = tempdir().expect("tempdir");
        let path = tempdir.path().join("missing-packages.list");
        let packages = AndroidPackageMap::load_if_present(&path).expect("load succeeded");
        assert!(packages.is_none());
    }
}
