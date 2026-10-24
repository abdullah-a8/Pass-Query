//! The cache file and its directory are private to the user, writing the
//! cache never follows a planted link or leaves a partial file, and a cache
//! someone else could have written is never read.

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

const BANK: Login = Login {
    id: "item-bank",
    title: "bank",
    username: "banker",
    email: "",
    password: "bank-secret",
};

fn harness() -> Harness {
    let mut h = Harness::new();
    h.vault("Personal", "share-personal")
        .login("share-personal", GITHUB)
        .login("share-personal", BANK);
    h
}

/// A fresh cache that lists "github" under the bank item's ID: if pq read
/// it, a search for github would copy the bank password.
fn substituted_cache() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    serde_json::json!({
        "version": 3,
        "vault_list": { "vaults": { "vaults": [{ "name": "Personal", "share_id": "share-personal" }] }, "timestamp": now },
        "vaults": [{
            "vault_key": "share:share-personal", "login_only": true, "timestamp": now,
            "items": { "items": [{ "id": "item-bank", "share_id": "share-personal",
                                    "title": "github", "item_type": "login" }] }
        }]
    })
    .to_string()
}

fn assert_cache_ignored(h: &Harness) {
    let out = h.run(&["github", "-p"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Username: octocat\nPassword: github-secret\n"
    );
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

#[test]
fn a_cache_reached_through_a_link_is_not_read() {
    let h = harness();
    let dir = h.cache_file().parent().unwrap().to_path_buf();
    fs::create_dir_all(&dir).unwrap();
    let planted = dir.parent().unwrap().join("planted.json");
    fs::write(&planted, substituted_cache()).unwrap();
    std::os::unix::fs::symlink(&planted, h.cache_file()).unwrap();

    assert_cache_ignored(&h);
}

#[test]
fn a_cache_file_others_can_write_is_not_read() {
    let h = harness();
    h.write_cache(&substituted_cache());
    fs::set_permissions(h.cache_file(), fs::Permissions::from_mode(0o666)).unwrap();

    assert_cache_ignored(&h);
}

#[test]
fn a_cache_in_a_directory_others_can_write_is_not_read() {
    let h = harness();
    h.write_cache(&substituted_cache());
    fs::set_permissions(h.cache_file(), fs::Permissions::from_mode(0o600)).unwrap();
    let dir = h.cache_file().parent().unwrap().to_path_buf();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();

    assert_cache_ignored(&h);
}

#[test]
fn a_cache_directory_reached_through_a_link_is_not_used() {
    let h = harness();
    let real = h
        .cache_file()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("elsewhere");
    fs::create_dir_all(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(real.join("vault-cache.json"), substituted_cache()).unwrap();
    fs::set_permissions(
        real.join("vault-cache.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::os::unix::fs::symlink(&real, h.cache_file().parent().unwrap()).unwrap();

    assert_cache_ignored(&h);
    // The linked directory may be shared; pq must not lock others out of it.
    assert_eq!(mode(&real), 0o755);
}
