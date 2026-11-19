//! `--version` and `--help` answer before any configuration is read: an operator
//! (or an installer) asking which build is on disk has no `JWT_SECRET` to offer.

use std::process::{Command, Output};

fn run_without_configuration(flag: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dockpanel-api"))
        .arg(flag)
        .env_clear()
        .output()
        .expect("the api binary must start")
}

#[test]
fn version_flags_answer_without_any_configuration() {
    for flag in ["--version", "-V"] {
        let out = run_without_configuration(flag);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        assert_eq!(stdout.trim(), format!("dockpanel-api {}", env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn help_flags_answer_without_any_configuration() {
    for flag in ["--help", "-h"] {
        let out = run_without_configuration(flag);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{flag}: {out:?}");
        assert!(stdout.contains("--version"), "{flag}: {stdout}");
        assert!(stdout.contains("--help"), "{flag}: {stdout}");
    }
}
