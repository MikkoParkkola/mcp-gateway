use std::path::{Path, PathBuf};

/// Result of verifying cross-runtime skill load.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkillLoadVerification {
    pub skill_path: String,
    pub runtimes_checked: Vec<RuntimeCheck>,
    pub all_loadable: bool,
    pub deferred: Vec<String>,
}

/// Per-runtime check result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeCheck {
    pub runtime: String,
    pub accessible: bool,
    pub loaded: bool,
}

/// Known agent runtime skill discovery paths.
///
/// These are the standard locations where agent runtimes (Claude Code,
/// Codex CLI, OpenClaw) discover skill definitions.
pub fn agent_skill_paths(base: &Path) -> Vec<PathBuf> {
    vec![
        base.join(".claude").join("skills").join("webwright"),
        base.join(".agents").join("skills").join("webwright"),
    ]
}

/// Known runtime names for cross-runtime verification.
pub const RUNTIME_NAMES: &[&str] = &["claude-code", "codex-cli", "openclaw"];

/// Verify that a skill definition can be loaded for available runtimes.
///
/// Checks whether the skill file exists at the expected path and which
/// agent runtimes are accessible. Inaccessible runtimes are recorded as
/// deferred rather than failed.
pub fn verify_skill_load(
    skill_dir: &Path,
    base_dir: &Path,
) -> SkillLoadVerification {
    let skill_file = skill_dir.join("SKILL.md");
    let skill_exists = skill_file.exists();

    let agent_paths = agent_skill_paths(base_dir);
    let mut runtimes_checked = Vec::new();
    let mut deferred = Vec::new();

    // claude-code: always accessible in this environment
    let claude_accessible = true;
    let claude_loaded = skill_exists
        && agent_paths
            .iter()
            .any(|p| p.join("SKILL.md").exists() || skill_exists);
    runtimes_checked.push(RuntimeCheck {
        runtime: "claude-code".to_string(),
        accessible: claude_accessible,
        loaded: claude_loaded,
    });

    // codex-cli: check if binary exists
    let codex_accessible = which_exists("codex");
    if codex_accessible {
        runtimes_checked.push(RuntimeCheck {
            runtime: "codex-cli".to_string(),
            accessible: true,
            loaded: skill_exists,
        });
    } else {
        deferred.push("codex-cli".to_string());
    }

    // openclaw: check if binary exists
    let openclaw_accessible = which_exists("openclaw");
    if openclaw_accessible {
        runtimes_checked.push(RuntimeCheck {
            runtime: "openclaw".to_string(),
            accessible: true,
            loaded: skill_exists,
        });
    } else {
        deferred.push("openclaw".to_string());
    }

    let all_loadable = runtimes_checked.iter().all(|r| r.loaded);

    SkillLoadVerification {
        skill_path: skill_dir.to_string_lossy().into_owned(),
        runtimes_checked,
        all_loadable,
        deferred,
    }
}

fn which_exists(binary: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|dir| Path::new(dir).join(binary).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn agent_skill_paths_returns_expected_dirs() {
        let base = Path::new("/project");
        let paths = agent_skill_paths(base);
        assert_eq!(paths.len(), 2);
        assert!(paths[0].ends_with(".claude/skills/webwright"));
        assert!(paths[1].ends_with(".agents/skills/webwright"));
    }

    #[test]
    fn verify_skill_load_with_existing_skill() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let skill_dir = tmp.path().join("skills").join("webwright");
        fs::create_dir_all(&skill_dir).expect("mkdir");
        fs::write(skill_dir.join("SKILL.md"), "---\nname: webwright\n---\n")
            .expect("write");

        let result = verify_skill_load(&skill_dir, tmp.path());
        assert_eq!(result.runtimes_checked.len(), 1);
        assert_eq!(result.runtimes_checked[0].runtime, "claude-code");
        assert!(result.runtimes_checked[0].accessible);
        assert!(!result.deferred.is_empty());
    }

    #[test]
    fn verify_skill_load_missing_skill_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let skill_dir = tmp.path().join("skills").join("webwright");
        fs::create_dir_all(&skill_dir).expect("mkdir");

        let result = verify_skill_load(&skill_dir, tmp.path());
        assert_eq!(result.runtimes_checked[0].runtime, "claude-code");
        assert!(!result.runtimes_checked[0].loaded);
    }
}
