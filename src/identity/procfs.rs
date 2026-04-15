//! `/proc` helpers for process identity enrichment.

use std::fs;
use std::path::PathBuf;

/// Read and normalize `/proc/<pid>/cmdline`.
#[must_use]
pub fn cmdline_for_pid(pid: u32) -> Option<String> {
    let path = PathBuf::from("/proc").join(pid.to_string()).join("cmdline");
    let bytes = fs::read(path).ok()?;
    normalize_cmdline_bytes(&bytes)
}

/// Convert raw `/proc/<pid>/cmdline` bytes into a readable command line.
#[must_use]
pub fn normalize_cmdline_bytes(bytes: &[u8]) -> Option<String> {
    let text = bytes
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .map(|segment| String::from_utf8_lossy(segment).trim().to_string())
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    (!text.is_empty()).then(|| text.join(" "))
}

/// Extract a stable program-like token from a command line.
#[must_use]
pub fn program_from_cmdline(cmdline: &str) -> Option<String> {
    let token = cmdline.split_whitespace().next()?.trim();
    let token = token.rsplit('/').next().unwrap_or(token).trim();
    (!token.is_empty()).then(|| token.to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalize_cmdline_bytes, program_from_cmdline};

    #[test]
    fn normalizes_proc_cmdline_bytes() {
        let cmdline =
            normalize_cmdline_bytes(b"/system/bin/netd\0--flag\0").expect("cmdline normalized");
        assert_eq!(cmdline, "/system/bin/netd --flag");
    }

    #[test]
    fn extracts_program_name_from_cmdline() {
        let program = program_from_cmdline("/system/bin/netd --flag").expect("program name");
        assert_eq!(program, "netd");
    }
}
