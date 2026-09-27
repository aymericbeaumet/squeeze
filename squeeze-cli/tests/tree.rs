//! Directory arguments: the tree is walked like ripgrep walks it, hidden
//! entries, ignore rules and binary files skipped, and every file is
//! scanned on its own thread.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn squeeze() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("squeeze").unwrap()
}

fn temp_tree(name: &str) -> PathBuf {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("squeeze-cli-tree-{id}-{name}"));
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("target")).unwrap();
    fs::create_dir_all(root.join(".hidden")).unwrap();
    // A `.git` entry makes the tree a repository, which is what activates
    // `.gitignore` (as for ripgrep).
    fs::create_dir_all(root.join(".git").join("hooks")).unwrap();
    fs::write(
        root.join(".git/hooks/sample"),
        "hook https://git.example/hook\n",
    )
    .unwrap();
    fs::write(root.join(".gitignore"), "target/\n").unwrap();
    fs::write(root.join("src/a.txt"), "see https://kept.example/a\n").unwrap();
    fs::write(root.join("src/f.rs"), "TODO: fix https://todo.example/f\n").unwrap();
    fs::write(
        root.join("src/d.bin"),
        b"see https://binary.example/d\x00\n",
    )
    .unwrap();
    fs::write(root.join("target/b.txt"), "see https://ignored.example/b\n").unwrap();
    fs::write(root.join(".hidden/c.txt"), "see https://hidden.example/c\n").unwrap();
    fs::write(root.join(".dotfile"), "see https://dot.example/e\n").unwrap();
    root
}

fn sorted_lines(output: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = String::from_utf8_lossy(output)
        .lines()
        .map(str::to_owned)
        .collect();
    lines.sort();
    lines
}

#[test]
fn directory_is_walked_with_ignore_rules_hidden_and_binary_files_skipped() {
    let root = temp_tree("default");
    let output = squeeze().args(["--url"]).arg(&root).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        sorted_lines(&output.stdout),
        vec!["https://kept.example/a", "https://todo.example/f"]
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn hidden_and_no_ignore_flags_widen_the_walk_but_never_enter_git() {
    let root = temp_tree("flags");
    let output = squeeze()
        .args(["--url", "--hidden", "--no-ignore"])
        .arg(&root)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        sorted_lines(&output.stdout),
        vec![
            "https://dot.example/e",
            "https://hidden.example/c",
            "https://ignored.example/b",
            "https://kept.example/a",
            "https://todo.example/f",
        ]
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn single_thread_walk_is_sorted_and_locations_carry_the_path() {
    let root = temp_tree("sorted");
    let src = root.join("src");
    let output = squeeze()
        .args(["--url", "--with-location", "-j", "1"])
        .arg(&src)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let a = format!("{}:1:5:https://kept.example/a", src.join("a.txt").display());
    let f = format!("{}:1:11:https://todo.example/f", src.join("f.rs").display());
    assert_eq!(text, format!("{a}\n{f}\n"));
    // Twice the same.
    let again = squeeze()
        .args(["--url", "--with-location", "-j", "1"])
        .arg(&src)
        .output()
        .unwrap();
    assert_eq!(again.stdout, output.stdout);
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn several_files_and_directories_are_walked_together() {
    let root = temp_tree("mixed");
    let output = squeeze()
        .args(["--url", "-j", "2"])
        .arg(root.join(".dotfile"))
        .arg(root.join("src"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        sorted_lines(&output.stdout),
        vec![
            "https://dot.example/e",
            "https://kept.example/a",
            "https://todo.example/f",
        ]
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn first_stops_at_the_first_result_of_a_walk() {
    let root = temp_tree("first");
    squeeze()
        .args(["--url", "--first"])
        .arg(root.join("src"))
        .assert()
        .success()
        .stdout(predicate::eq("https://kept.example/a\n"));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn buffered_output_collects_every_file() {
    let root = temp_tree("json");
    squeeze()
        .args(["--url", "--output", "json", "--sort"])
        .arg(&root)
        .assert()
        .success()
        .stdout(predicate::eq(
            "[\"https://kept.example/a\",\"https://todo.example/f\"]\n",
        ));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn unreadable_entries_are_reported_and_the_walk_goes_on() {
    let root = temp_tree("missing");
    squeeze()
        .args(["--url"])
        .arg(root.join("does-not-exist"))
        .arg(root.join("src"))
        .assert()
        .success()
        .stderr(predicate::str::contains("does-not-exist"))
        .stdout(predicate::str::contains("https://kept.example/a"));
    fs::remove_dir_all(&root).unwrap();
}
