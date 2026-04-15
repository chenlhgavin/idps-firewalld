//! Interface classification into `wifi/mobile` buckets.

use std::fs;
use std::path::Path;

/// Logical network class for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkClass {
    /// Wi-Fi traffic bucket.
    Wifi,
    /// Mobile/cellular traffic bucket.
    Mobile,
    /// Unclassified interface bucket.
    Other,
}

/// Map an interface name into the reporting class.
#[must_use]
pub fn classify_interface(name: &str) -> NetworkClass {
    let lower = name.to_ascii_lowercase();
    if lower.contains("wlan") || lower.contains("wifi") {
        NetworkClass::Wifi
    } else if lower.contains("rmnet") || lower.contains("ccmni") || lower.contains("mobile") {
        NetworkClass::Mobile
    } else {
        NetworkClass::Other
    }
}

/// Resolve an interface index into a reporting class using `/sys/class/net`.
#[must_use]
pub fn classify_ifindex(ifindex: u32) -> NetworkClass {
    interface_name_for_ifindex(ifindex)
        .map_or(NetworkClass::Other, |name| classify_interface(&name))
}

/// Resolve an interface index into its current kernel device name.
#[must_use]
pub fn interface_name_for_ifindex(ifindex: u32) -> Option<String> {
    let entries = fs::read_dir(Path::new("/sys/class/net")).ok()?;
    for entry in entries.flatten() {
        let ifindex_path = entry.path().join("ifindex");
        let Ok(value) = fs::read_to_string(ifindex_path) else {
            continue;
        };
        let Ok(parsed) = value.trim().parse::<u32>() else {
            continue;
        };
        if parsed == ifindex {
            return entry.file_name().to_str().map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{NetworkClass, classify_ifindex, classify_interface};

    #[test]
    fn classifies_wifi_interfaces() {
        assert_eq!(classify_interface("wlan0"), NetworkClass::Wifi);
    }

    #[test]
    fn classifies_mobile_interfaces() {
        assert_eq!(classify_interface("rmnet_data0"), NetworkClass::Mobile);
    }

    #[test]
    fn unknown_ifindex_defaults_to_other() {
        assert_eq!(classify_ifindex(u32::MAX), NetworkClass::Other);
    }
}
