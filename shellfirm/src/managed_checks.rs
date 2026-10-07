//! Default checks supplied by the separate Jamf checks package.

use std::{collections::HashSet, path::Path};

use crate::{checks::Check, error::{Error, Result}};

/// Compile-time selection, never a user environment-variable override.
#[must_use]
pub const fn source() -> &'static str {
    match option_env!("SHELLFIRM_MANAGED_CHECKS_PATH") {
        Some(path) => path,
        None => "embedded",
    }
}

/// Parse a complete default-check catalog; reject empty or ambiguous catalogs.
///
/// # Errors
/// Returns an error for invalid YAML, regexes, duplicate IDs or missing metadata.
pub fn parse(content: &str) -> Result<Vec<Check>> {
    let checks: Vec<Check> = serde_yaml::from_str(content)?;
    if checks.is_empty() {
        return Err(Error::Config("default-check catalog is empty".into()));
    }
    let mut ids = HashSet::new();
    for check in &checks {
        if check.id.trim().is_empty() || check.from.trim().is_empty()
            || check.description.trim().is_empty() || !ids.insert(&check.id)
        {
            return Err(Error::Config(format!("invalid or duplicate default check: {}", check.id)));
        }
    }
    let warnings = crate::checks::validate_checks(&checks);
    if !warnings.is_empty() {
        return Err(Error::Config(warnings.join("; ")));
    }
    Ok(checks)
}

/// Load the fixed managed catalog with no fallback to embedded or user checks.
///
/// # Errors
/// Returns an error when the catalog or its managed parent directories are
/// missing, symlinked, not root-owned, writable by other users or invalid.
pub fn load(path: &Path) -> Result<Vec<Check>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // File, checks directory, ShellFirm directory and VGS directory.
        for (index, component) in path.ancestors().take(4).enumerate() {
            let metadata = std::fs::symlink_metadata(component)?;
            if metadata.file_type().is_symlink() || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || (index == 0 && !metadata.is_file())
                || (index > 0 && !metadata.is_dir())
            {
                return Err(Error::Config(format!("unsafe managed checks path: {}", component.display())));
            }
        }
        parse(&std::fs::read_to_string(path)?)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Error::Config("managed checks require Unix file ownership".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: &str = "- id: aws:fixture\n  from: aws\n  test: '^aws fixture$'\n  description: fixture\n";

    #[test]
    fn accepts_a_valid_catalog() {
        assert_eq!(parse(CHECK).unwrap()[0].id, "aws:fixture");
    }

    #[test]
    fn rejects_empty_malformed_and_duplicate_catalogs() {
        for input in ["[]".to_string(), "[".to_string(), format!("{CHECK}{CHECK}"),
            CHECK.replace("^aws fixture$", "["), CHECK.replace("aws:fixture", "")]
        {
            assert!(parse(&input).is_err());
        }
    }

    #[test]
    fn missing_catalog_is_an_error() {
        assert!(load(Path::new("/nonexistent-vgs-checks/default-checks.yaml")).is_err());
    }
}
