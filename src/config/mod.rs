//! Loading and saving `config.yaml`.

pub mod model;
pub mod paths;

use std::path::{Path, PathBuf};

pub use model::*;
pub use paths::MossPaths;

use crate::error::{MossError, Result};

/// Resolution order: `--config`, `MOSS_CONFIG`, platform default (spec §24).
pub fn config_path(flag: Option<&Path>, paths: &MossPaths) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Some(p) = std::env::var_os("MOSS_CONFIG").filter(|s| !s.is_empty()) {
        return PathBuf::from(p);
    }
    paths.config_file()
}

pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            MossError::NotConfigured
        } else {
            MossError::Config(format!("cannot read {}: {e}", path.display()))
        }
    })?;
    parse(&text).map_err(|e| MossError::Config(format!("{}: {e}", path.display())))
}

pub fn load_or_default(path: &Path) -> Result<Config> {
    match load(path) {
        Ok(c) => Ok(c),
        Err(MossError::NotConfigured) => Ok(Config::default()),
        Err(e) => Err(e),
    }
}

pub fn parse(text: &str) -> Result<Config> {
    if text.trim().is_empty() {
        return Ok(Config::default());
    }
    let cfg: Config = serde_yaml_ng::from_str(text)?;
    if cfg.schema_version > CONFIG_SCHEMA_VERSION {
        return Err(MossError::Config(format!(
            "config schema_version {} is newer than this moss understands ({})",
            cfg.schema_version, CONFIG_SCHEMA_VERSION
        )));
    }
    Ok(cfg)
}

pub fn save(path: &Path, cfg: &Config) -> Result<()> {
    if let Some(parent) = path.parent() {
        paths::create_private_dir(parent)?;
    }
    let text = render(cfg)?;
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, text)?;
    paths::make_private_file(&tmp)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn render(cfg: &Config) -> Result<String> {
    let body = serde_yaml_ng::to_string(cfg)?;
    Ok(format!(
        "# moss configuration. No secrets belong in this file: the repository password\n# lives in the OS credential store (see `moss recovery show`).\n{body}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_not_configured() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(&tmp.path().join("nope.yaml")),
            Err(MossError::NotConfigured)
        ));
        assert_eq!(
            load_or_default(&tmp.path().join("nope.yaml")).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn save_and_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("cfg/config.yaml");
        let mut c = Config::default();
        c.profile.identity = "rhys".into();
        c.include.push(PathRule::new("~/Projects"));
        save(&p, &c).unwrap();
        let back = load(&p).unwrap();
        assert_eq!(back, c);
        assert!(paths::mode_is_private(&p, 0o600).unwrap());
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .starts_with("# moss configuration")
        );
    }

    #[test]
    fn newer_schema_rejected() {
        assert!(parse("schema_version: 99\n").is_err());
        assert!(parse("").is_ok());
    }
}
