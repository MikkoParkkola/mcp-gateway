// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::path::Path;

const FULL_IMAGE: &str = "ghcr.io/mikkoparkkola/mcp-gateway:latest-full";

pub(super) struct Remedy {
    pub(super) hint: String,
    pub(super) manual_fix: String,
}

pub(super) fn runs_in_a_container() -> bool {
    Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("container").is_some()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

fn binary_name(bin: &str) -> &str {
    Path::new(bin)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(bin)
}

fn loads_the_runtime(bin: &str) -> bool {
    matches!(binary_name(bin), "node" | "npx" | "npm" | "uv" | "uvx")
}

pub(super) fn missing_binary_remedy(bin: &str, in_container: bool) -> Option<Remedy> {
    if in_container && loads_the_runtime(bin) {
        return Some(Remedy {
            hint: format!(
                "this image carries no {bin} runtime; the -full variant of this tag does, e.g. {FULL_IMAGE}"
            ),
            manual_fix: format!("docker pull {FULL_IMAGE}"),
        });
    }
    match binary_name(bin) {
        "node" | "npx" | "npm" => Some(Remedy {
            hint: "Install the command: install Node.js from https://nodejs.org".to_string(),
            manual_fix: "install Node.js from https://nodejs.org".to_string(),
        }),
        "uv" | "uvx" => Some(Remedy {
            hint: "Install the command: install uv from https://docs.astral.sh/uv/".to_string(),
            manual_fix: "install uv from https://docs.astral.sh/uv/".to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::missing_binary_remedy;

    #[test]
    fn a_container_is_pointed_at_the_image_that_carries_the_runtime() {
        for bin in ["npx", "uvx", "node", "npm", "/usr/bin/npx"] {
            let remedy = missing_binary_remedy(bin, true).expect("container remedy");
            assert!(remedy.hint.contains(super::FULL_IMAGE), "{}", remedy.hint);
            assert_eq!(
                remedy.manual_fix,
                format!("docker pull {}", super::FULL_IMAGE)
            );
        }
    }

    #[test]
    fn a_host_still_gets_the_install_instructions() {
        let remedy = missing_binary_remedy("npx", false).expect("host remedy");
        assert_eq!(remedy.manual_fix, "install Node.js from https://nodejs.org");
        assert!(missing_binary_remedy("bat", true).is_none());
        assert!(missing_binary_remedy("uvx", false).is_some());
        assert!(missing_binary_remedy("/usr/bin/npx", false).is_some());
    }
}
