//! The cache file and its directory are private to the user, and writing the
//! cache never follows a planted link or leaves a partial file.

#![cfg(unix)]

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use support::{Harness, Login, stderr};

const GITHUB: Login = Login {
    id: "item-github",
    title: "github",
    username: "octocat",
    email: "",
    password: "github-secret",
};

fn harness() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB);
    h
}

fn mode(path: &std::path::Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn the_cache_directory_is_private() {
    let h = harness();

    assert!(h.run(&["github", "-p"]).status.success());

    assert_eq!(mode(h.cache_file().parent().unwrap()), 0o700);
}

#[test]
fn an_existing_open_cache_directory_is_made_private() {
    let h = harness();
    let dir = h.cache_file().parent().unwrap().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(h.run(&["github", "-p"]).status.success());

    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn a_link_planted_at_the_cache_path_is_replaced_not_followed() {
    let h = harness();
    let dir = h.cache_file().parent().unwrap().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    let victim = dir.parent().unwrap().join("victim.txt");
    fs::write(&victim, "keep me").unwrap();
    std::os::unix::fs::symlink(&victim, h.cache_file()).unwrap();

    let out = h.run(&["github", "-p"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep me");
    let meta = fs::symlink_metadata(h.cache_file()).unwrap();
    assert!(meta.file_type().is_file(), "cache is a regular file again");
    assert_eq!(mode(&h.cache_file()), 0o600);
}

#[test]
fn writing_the_cache_leaves_only_the_cache_file() {
    let h = harness();

    assert!(h.run(&["github", "-p"]).status.success());
    assert!(h.run(&["github", "-r", "-p"]).status.success());

    let names: Vec<String> = fs::read_dir(h.cache_file().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["vault-cache.json"]);
    h.cache_json(); // still valid and secret-free
}
