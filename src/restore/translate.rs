//! Post-restore path report (spec §15): read-only scanners that find absolute
//! paths embedded in restored configuration files which will not resolve on
//! this machine, and suggest the translated path. Nothing is rewritten.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::platform::Platform;

/// One embedded path that will not resolve here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Home-relative display form, e.g. `~/.ssh/config`.
    pub file: String,
    pub line: usize,
    /// The directive or key the path was found under.
    pub key: String,
    pub path: String,
    pub suggestion: String,
}

/// Where the snapshot came from.
#[derive(Debug, Clone)]
pub struct Origin {
    pub home: String,
    pub user: String,
}

impl Origin {
    /// Every prefix that means "the origin home": the recorded home plus the
    /// OS-conventional forms for the origin user (`/Users/<u>`, `/home/<u>`,
    /// `C:\Users\<u>`), so a Linux `.gitconfig` that mentions `/home/rhys`
    /// is still recognised when `source_home` was recorded differently.
    pub fn prefixes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let home = self.home.trim_end_matches(['/', '\\']).to_string();
        if !home.is_empty() {
            out.push(home);
        }
        if !self.user.is_empty() {
            for p in [
                format!("/Users/{}", self.user),
                format!("/home/{}", self.user),
                format!("C:\\Users\\{}", self.user),
                format!("C:/Users/{}", self.user),
            ] {
                if !out.iter().any(|o| o.eq_ignore_ascii_case(&p)) {
                    out.push(p);
                }
            }
        }
        out
    }
}

/// A file moss knows how to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    SshConfig,
    GitConfig,
    KubeConfig,
    AwsConfig,
    ShellRc,
    DockerConfig,
}

/// Which scanner applies to a home-relative path (forward slashes).
pub fn kind_for(home_relative: &str) -> Option<FileKind> {
    let rel = home_relative.trim_start_matches("~/");
    Some(match rel {
        ".ssh/config" => FileKind::SshConfig,
        ".gitconfig" | ".config/git/config" => FileKind::GitConfig,
        ".kube/config" => FileKind::KubeConfig,
        ".aws/config" | ".aws/credentials" => FileKind::AwsConfig,
        ".docker/config.json" => FileKind::DockerConfig,
        ".zshrc" | ".bashrc" | ".bash_profile" | ".profile" | ".zprofile" | ".zshenv"
        | ".bash_login" => FileKind::ShellRc,
        _ => return None,
    })
}

/// A path found in a file, before the "will it resolve" filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Embedded {
    pub line: usize,
    pub key: String,
    pub path: String,
}

/// Extract candidate absolute paths from a file's text.
pub fn scan_text(kind: FileKind, text: &str) -> Vec<Embedded> {
    let mut out = Vec::new();
    let mut section = String::new();
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match kind {
            FileKind::SshConfig => {
                let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
                let key = parts.next().unwrap_or("");
                let value = parts.next().unwrap_or("").trim();
                if SSH_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
                    push_paths(&mut out, line_no, key, value);
                }
            }
            FileKind::GitConfig => {
                if line.starts_with('[') {
                    section = line.to_string();
                    if let Some(rest) = line
                        .strip_prefix("[includeIf \"gitdir:")
                        .or_else(|| line.strip_prefix("[includeIf \"gitdir/i:"))
                    {
                        let value = rest.trim_end_matches(['"', ']']).trim_end_matches("\"]");
                        push_paths(&mut out, line_no, "includeIf gitdir", value);
                    }
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let key = if section.is_empty() {
                        k.trim().to_string()
                    } else {
                        format!("{} {}", section, k.trim())
                    };
                    push_paths(&mut out, line_no, &key, v.trim());
                }
            }
            FileKind::KubeConfig => {
                let body = line.trim_start_matches("- ").trim();
                if let Some((k, v)) = body.split_once(':') {
                    let key = k.trim();
                    let value = v.trim();
                    if KUBE_KEYS.contains(&key) || looks_absolute(value) {
                        push_paths(&mut out, line_no, key, value);
                    }
                } else if looks_absolute(body) {
                    push_paths(&mut out, line_no, "args", body);
                }
            }
            FileKind::AwsConfig => {
                if line.starts_with('[') {
                    section = line.to_string();
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let key = k.trim();
                    push_paths(&mut out, line_no, key, v.trim());
                }
            }
            FileKind::ShellRc => {
                let interesting = line.starts_with("source ")
                    || line.starts_with(". ")
                    || line.starts_with("export ")
                    || line.contains("PATH")
                    || line.starts_with("alias ")
                    || line.starts_with("eval ");
                if interesting {
                    let key = line
                        .split(|c: char| c.is_whitespace() || c == '=')
                        .next()
                        .unwrap_or("line");
                    push_paths(&mut out, line_no, key, line);
                }
            }
            FileKind::DockerConfig => {
                if line.contains("credsStore")
                    || line.contains("credHelpers")
                    || line.contains("\"")
                {
                    let key = if line.contains("credHelpers") {
                        "credHelpers"
                    } else if line.contains("credsStore") {
                        "credsStore"
                    } else {
                        line.split('"').nth(1).unwrap_or("value")
                    };
                    push_paths(&mut out, line_no, key, line);
                }
            }
        }
    }
    out
}

const SSH_KEYS: [&str; 7] = [
    "IdentityFile",
    "ControlPath",
    "UserKnownHostsFile",
    "Include",
    "CertificateFile",
    "IdentityAgent",
    "GlobalKnownHostsFile",
];

const KUBE_KEYS: [&str; 5] = [
    "client-certificate",
    "client-key",
    "certificate-authority",
    "command",
    "tokenFile",
];

fn looks_absolute(s: &str) -> bool {
    let s = s.trim_matches(['"', '\'']);
    s.starts_with('/')
        || s.starts_with("~/")
        || (s.len() > 2
            && s.as_bytes()[0].is_ascii_alphabetic()
            && s.as_bytes()[1] == b':'
            && matches!(s.as_bytes()[2], b'\\' | b'/'))
}

/// Pull every absolute-looking path token out of `value`.
fn push_paths(out: &mut Vec<Embedded>, line: usize, key: &str, value: &str) {
    for token in path_tokens(value) {
        out.push(Embedded {
            line,
            key: key.to_string(),
            path: token,
        });
    }
}

/// Tokens that start like an absolute path (`/x`, `~/x`, `C:\x`) and run to
/// the next delimiter.
pub fn path_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &value[i..];
        let starts = rest.starts_with('/')
            || rest.starts_with("~/")
            || (rest.len() > 2
                && bytes[i].is_ascii_alphabetic()
                && bytes[i + 1] == b':'
                && matches!(bytes[i + 2], b'\\' | b'/'));
        let boundary = i == 0
            || !(bytes[i - 1].is_ascii_alphanumeric()
                || bytes[i - 1] == b'.'
                || bytes[i - 1] == b'_'
                || bytes[i - 1] == b'-'
                || bytes[i - 1] == b'/'
                || bytes[i - 1] == b'\\');
        if starts && boundary {
            let windows = bytes[i] != b'/' && bytes[i] != b'~';
            let mut end = i + if windows { 3 } else { 1 };
            while end < bytes.len() {
                let c = bytes[end];
                let stop = c.is_ascii_whitespace()
                    || matches!(
                        c,
                        b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'>' | b'|'
                    )
                    || (c == b':' && !windows)
                    || (c == b'=' && !windows);
                if stop {
                    break;
                }
                end += 1;
            }
            // A `~/` alone or a bare `/` is not a path worth reporting.
            let token = value[i..end].trim_end_matches(['/', '\\', '.']);
            if token.len() > 2 {
                out.push(token.to_string());
            }
            i = end.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

/// Where a path under an origin prefix would live on this machine.
pub fn translate(
    path: &str,
    origin: &Origin,
    dest_home: &Path,
    dest_os: Platform,
) -> Option<String> {
    for prefix in origin.prefixes() {
        let matched =
            if path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(&prefix) {
                let rest = &path[prefix.len()..];
                rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\')
            } else {
                false
            };
        if matched {
            let rest = &path[prefix.len()..];
            let mut suggestion = dest_home.display().to_string();
            let sep = if dest_os == Platform::Windows {
                '\\'
            } else {
                '/'
            };
            let rest: String = rest
                .chars()
                .map(|c| if c == '/' || c == '\\' { sep } else { c })
                .collect();
            suggestion.push_str(&rest);
            return Some(suggestion);
        }
    }
    None
}

/// Filter embedded paths down to findings: under an origin prefix and not
/// resolvable here (`exists` is injectable for tests).
pub fn findings_for(
    file_display: &str,
    embedded: &[Embedded],
    origin: &Origin,
    dest_home: &Path,
    dest_os: Platform,
    exists: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in embedded {
        let Some(suggestion) = translate(&e.path, origin, dest_home, dest_os) else {
            continue;
        };
        if exists(&e.path) {
            continue;
        }
        if out
            .iter()
            .any(|f: &Finding| f.line == e.line && f.path == e.path)
        {
            continue;
        }
        out.push(Finding {
            file: file_display.to_string(),
            line: e.line,
            key: e.key.clone(),
            path: e.path.clone(),
            suggestion,
        });
    }
    out
}

/// Scan every restored file moss has a scanner for. `restored` are absolute
/// destination paths; `dest_home` is what `~` means on this machine.
pub fn scan_restored(
    restored: &[PathBuf],
    dest_home: &Path,
    origin: &Origin,
    dest_os: Platform,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for path in restored {
        let display = crate::model::home_relative(path, dest_home);
        let Some(kind) = kind_for(&display) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let embedded = scan_text(kind, &text);
        out.extend(findings_for(
            &display,
            &embedded,
            origin,
            dest_home,
            dest_os,
            &|p| Path::new(p).exists(),
        ));
    }
    out.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin {
            home: "/Users/rhys".into(),
            user: "rhys".into(),
        }
    }

    #[test]
    fn ssh_config_directives() {
        let text = "Host *\n  IdentityFile /Users/rhys/.ssh/id_ed25519\n  ControlPath /Users/rhys/.ssh/cm-%r@%h:%p\n  UserKnownHostsFile ~/.ssh/known_hosts\n# IdentityFile /Users/rhys/ignored\nInclude /Users/rhys/.ssh/work.conf\n  User rhys\n";
        let found = scan_text(FileKind::SshConfig, text);
        let paths: Vec<&str> = found.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/Users/rhys/.ssh/id_ed25519",
                "/Users/rhys/.ssh/cm-%r@%h",
                "~/.ssh/known_hosts",
                "/Users/rhys/.ssh/work.conf"
            ]
        );
        assert_eq!(found[0].line, 2);
        assert_eq!(found[0].key, "IdentityFile");
        let f = findings_for(
            "~/.ssh/config",
            &found,
            &origin(),
            Path::new("/home/rhys"),
            Platform::Linux,
            &|_| false,
        );
        assert_eq!(f.len(), 3, "{f:?}");
        assert_eq!(f[0].suggestion, "/home/rhys/.ssh/id_ed25519");
        assert_eq!(f[2].path, "/Users/rhys/.ssh/work.conf");
        // Paths that exist here are not reported.
        let f = findings_for(
            "~/.ssh/config",
            &found,
            &origin(),
            Path::new("/home/rhys"),
            Platform::Linux,
            &|p| p.ends_with("id_ed25519"),
        );
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn gitconfig_sections_and_values() {
        let text = "[user]\n\tname = Rhys\n[includeIf \"gitdir:/Users/rhys/work/\"]\n\tpath = /Users/rhys/.gitconfig-work\n[core]\n\texcludesfile = /Users/rhys/.gitignore_global\n[credential]\n\thelper = /usr/local/bin/git-credential-manager\n\thelper = /home/rhys/bin/helper\n";
        let found = scan_text(FileKind::GitConfig, text);
        let keys: Vec<String> = found
            .iter()
            .map(|e| format!("{}={}", e.key, e.path))
            .collect();
        assert_eq!(
            keys,
            vec![
                "includeIf gitdir=/Users/rhys/work",
                "[includeIf \"gitdir:/Users/rhys/work/\"] path=/Users/rhys/.gitconfig-work",
                "[core] excludesfile=/Users/rhys/.gitignore_global",
                "[credential] helper=/usr/local/bin/git-credential-manager",
                "[credential] helper=/home/rhys/bin/helper",
            ]
        );
        let f = findings_for(
            "~/.gitconfig",
            &found,
            &origin(),
            Path::new("/home/revans"),
            Platform::Linux,
            &|_| false,
        );
        // /usr/local is not under the origin home; /home/rhys is the
        // OS-pattern form for the origin user and is translated.
        let suggestions: Vec<&str> = f.iter().map(|x| x.suggestion.as_str()).collect();
        assert_eq!(
            suggestions,
            vec![
                "/home/revans/work",
                "/home/revans/.gitconfig-work",
                "/home/revans/.gitignore_global",
                "/home/revans/bin/helper",
            ]
        );
    }

    #[test]
    fn kube_aws_shell_docker() {
        let kube = "users:\n- name: minikube\n  user:\n    client-certificate: /Users/rhys/.minikube/client.crt\n    client-key: /Users/rhys/.minikube/client.key\n    exec:\n      command: /Users/rhys/bin/kubelogin\n      args:\n      - --cache-dir\n      - /Users/rhys/.kube/cache\n";
        let found = scan_text(FileKind::KubeConfig, kube);
        let paths: Vec<&str> = found.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/Users/rhys/.minikube/client.crt",
                "/Users/rhys/.minikube/client.key",
                "/Users/rhys/bin/kubelogin",
                "/Users/rhys/.kube/cache"
            ]
        );
        assert_eq!(found[0].key, "client-certificate");
        assert_eq!(found[3].key, "args");

        let aws = "[default]\nregion = eu-west-2\ncredential_process = /Users/rhys/bin/aws-login --profile default\nca_bundle = /Users/rhys/certs/ca.pem\n";
        let found = scan_text(FileKind::AwsConfig, aws);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].key, "credential_process");
        assert_eq!(found[0].path, "/Users/rhys/bin/aws-login");

        let rc = "export PATH=\"/Users/rhys/.cargo/bin:/usr/local/bin:$PATH\"\nsource /Users/rhys/.config/zsh/aliases.zsh\nalias ll='ls -la'\necho hi /Users/rhys/not-interesting\n. /Users/rhys/.profile.local\n";
        let found = scan_text(FileKind::ShellRc, rc);
        let paths: Vec<&str> = found.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/Users/rhys/.cargo/bin",
                "/usr/local/bin",
                "/Users/rhys/.config/zsh/aliases.zsh",
                "/Users/rhys/.profile.local"
            ]
        );
        assert_eq!(found[0].key, "export");
        assert_eq!(found[1].line, 1);

        let docker = "{\n  \"credsStore\": \"/Users/rhys/bin/docker-credential-pass\",\n  \"credHelpers\": { \"ghcr.io\": \"osxkeychain\" }\n}\n";
        let found = scan_text(FileKind::DockerConfig, docker);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key, "credsStore");
        assert_eq!(found[0].path, "/Users/rhys/bin/docker-credential-pass");
    }

    #[test]
    fn translation_across_platforms() {
        let o = origin();
        assert_eq!(
            translate(
                "/Users/rhys/.ssh/id",
                &o,
                Path::new("/home/rhys"),
                Platform::Linux
            )
            .unwrap(),
            "/home/rhys/.ssh/id"
        );
        assert_eq!(
            translate(
                "/home/rhys/x",
                &o,
                Path::new("/Users/rhys"),
                Platform::MacOs
            )
            .unwrap(),
            "/Users/rhys/x"
        );
        assert_eq!(
            translate(
                "/Users/rhys/a/b",
                &o,
                Path::new("C:\\Users\\rhys"),
                Platform::Windows
            )
            .unwrap(),
            "C:\\Users\\rhys\\a\\b"
        );
        assert_eq!(
            translate(
                "C:\\Users\\rhys\\a",
                &o,
                Path::new("/home/rhys"),
                Platform::Linux
            )
            .unwrap(),
            "/home/rhys/a"
        );
        assert!(
            translate(
                "/Users/rhysx/a",
                &o,
                Path::new("/home/rhys"),
                Platform::Linux
            )
            .is_none()
        );
        assert!(translate("/usr/bin/x", &o, Path::new("/home/rhys"), Platform::Linux).is_none());
        let win = Origin {
            home: "C:\\Users\\rhys".into(),
            user: "rhys".into(),
        };
        assert_eq!(
            translate(
                "c:\\users\\rhys\\.ssh\\id",
                &win,
                Path::new("/home/rhys"),
                Platform::Linux
            )
            .unwrap(),
            "/home/rhys/.ssh/id"
        );
    }

    #[test]
    fn kinds_and_scan_restored() {
        assert_eq!(kind_for("~/.ssh/config"), Some(FileKind::SshConfig));
        assert_eq!(kind_for("~/.zshrc"), Some(FileKind::ShellRc));
        assert_eq!(kind_for("~/Documents/x"), None);
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        // A made-up origin user so the "does it exist here" check is hermetic.
        let origin = Origin {
            home: "/Users/moss-origin-user".into(),
            user: "moss-origin-user".into(),
        };
        std::fs::write(
            home.join(".ssh/config"),
            "IdentityFile /Users/moss-origin-user/.ssh/id_ed25519\n",
        )
        .unwrap();
        std::fs::write(
            home.join("plain.txt"),
            "IdentityFile /Users/moss-origin-user/x\n",
        )
        .unwrap();
        let f = scan_restored(
            &[home.join(".ssh/config"), home.join("plain.txt")],
            home,
            &origin,
            Platform::current(),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].file, "~/.ssh/config");
        assert_eq!(f[0].line, 1);
        assert_eq!(
            f[0].suggestion,
            home.join(".ssh").join("id_ed25519").display().to_string()
        );
    }
}
