#![cfg(unix)]

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_agent-browser");
const SESSION: &str = "page-headers-test";
const SECRET: &str = "SECRET-TOKEN-XYZ";
const HEADER_NAME: &str = "X-Probe-Name";

fn command(home: &TempDir) -> Command {
    let root = home.path();
    let mut command = Command::new(BIN);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root)
        .env("USERPROFILE", root)
        .env("TMPDIR", root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("AGENT_BROWSER_SOCKET_DIR", root.join("s"))
        .env("AGENT_BROWSER_EXECUTABLE_PATH", root.join("no-such-chrome"))
        .env("NO_COLOR", "1")
        .current_dir(root)
        .args(["--session", SESSION]);
    command
}

fn socket_dir_entries(home: &TempDir) -> Vec<String> {
    let dir = home.path().join("s");
    match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Asserts a rejected invalid-header run: non-zero exit, no daemon files,
/// no browser launch attempt, and no echo of the caller's header input.
fn assert_rejected_before_daemon(output: &Output, label: &str, forbidden: &[&str]) {
    assert!(!output.status.success(), "{label}: {output:?}");
    let text = combined(output);
    assert!(
        !text.contains("Chrome") && !text.contains("executable") && !text.contains("launch"),
        "{label}: reached browser launch: {text}"
    );
    for needle in forbidden {
        assert!(!text.contains(needle), "{label}: echoed {needle}: {text}");
    }
}

fn run_invalid(home: &TempDir, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = command(home);
    cmd.args(args);
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn invalid_headers_are_rejected_before_daemon_start_on_navigation_and_read() {
    let invalid = [
        // Array, the exact shape from the bug report.
        r#"["X-Test"]"#.to_string(),
        // Non-string members.
        format!(r#"{{"{HEADER_NAME}":1}}"#),
        format!(r#"{{"{HEADER_NAME}":null}}"#),
        format!(r#"{{"{HEADER_NAME}":{{"token":"{SECRET}"}}}}"#),
        format!(r#"{{"{HEADER_NAME}":["{SECRET}"]}}"#),
        // Mixed valid and invalid members must still be rejected.
        format!(r#"{{"Authorization":"Bearer {SECRET}","n":1}}"#),
        // Malformed JSON that carries a secret.
        format!(r#"{{"Authorization":"Bearer {SECRET}",}}"#),
        format!("not json {SECRET}"),
    ];
    let forbidden = [SECRET, HEADER_NAME, "Authorization"];
    for raw in &invalid {
        for args in [
            vec!["open", "http://127.0.0.1:9/test", "--headers", raw.as_str()],
            vec!["goto", "http://127.0.0.1:9/test", "--headers", raw.as_str()],
            vec!["navigate", "http://127.0.0.1:9/test", "--headers", raw.as_str()],
            vec!["read", "http://127.0.0.1:9/test", "--headers", raw.as_str()],
        ] {
            let home = TempDir::new().unwrap();
            std::fs::create_dir(home.path().join("s")).unwrap();
            let output = run_invalid(&home, &args, None);
            let label = format!("{args:?}");
            assert_rejected_before_daemon(&output, &label, &forbidden);
            assert!(
                socket_dir_entries(&home).is_empty(),
                "{label}: daemon files created: {:?}",
                socket_dir_entries(&home)
            );
        }
    }
}

#[test]
fn invalid_headers_error_uses_fixed_message() {
    let home = TempDir::new().unwrap();
    let output = run_invalid(
        &home,
        &["open", "http://127.0.0.1:9/test", "--headers", r#"["X-Test"]"#],
        None,
    );
    assert!(!output.status.success());
    let text = combined(&output);
    assert!(
        text.contains("--headers must be a JSON object with string values"),
        "{text}"
    );
    assert!(!text.contains("X-Test"), "{text}");
}

#[test]
fn invalid_headers_json_output_is_still_an_error_without_echo() {
    let home = TempDir::new().unwrap();
    let raw = format!(r#"{{"{HEADER_NAME}":{{"token":"{SECRET}"}}}}"#);
    let output = run_invalid(
        &home,
        &[
            "--json",
            "open",
            "http://127.0.0.1:9/test",
            "--headers",
            raw.as_str(),
        ],
        None,
    );
    assert_rejected_before_daemon(&output, "json open", &[SECRET, HEADER_NAME]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("json output not parseable: {e}: {stdout}");
    });
    assert_eq!(value["success"], false, "{value}");
    assert!(socket_dir_entries(&home).is_empty());
}

#[test]
fn invalid_headers_on_batch_are_rejected_before_daemon_start() {
    let forbidden = [SECRET, HEADER_NAME];
    let bad = format!(r#"{{"{HEADER_NAME}":{{"token":"{SECRET}"}}}}"#);

    // Batch given as arguments.
    let home = TempDir::new().unwrap();
    let output = run_invalid(
        &home,
        &[
            "batch",
            "--json",
            "--headers",
            bad.as_str(),
            "open http://127.0.0.1:9/test",
        ],
        None,
    );
    assert_rejected_before_daemon(&output, "batch args", &forbidden);
    assert!(socket_dir_entries(&home).is_empty(), "batch args");

    // Batch read from stdin.
    let home = TempDir::new().unwrap();
    let output = run_invalid(
        &home,
        &["batch", "--json", "--headers", bad.as_str()],
        Some(r#"[["open","http://127.0.0.1:9/test"]]"#),
    );
    assert_rejected_before_daemon(&output, "batch stdin", &forbidden);
    assert!(socket_dir_entries(&home).is_empty(), "batch stdin");
}

#[test]
fn set_headers_rejects_non_object_and_non_string_json_before_daemon() {
    for raw in [
        "[1]".to_string(),
        r#"{"a":1}"#.to_string(),
        format!(r#"{{"a":{{"token":"{SECRET}"}}}}"#),
        "not json".to_string(),
    ] {
        let home = TempDir::new().unwrap();
        let output = run_invalid(&home, &["set", "headers", raw.as_str()], None);
        assert_rejected_before_daemon(&output, &format!("set headers {raw}"), &[SECRET]);
        assert!(socket_dir_entries(&home).is_empty(), "set headers {raw}");
    }
}

/// Starts a fake daemon on the session socket with a matching version sidecar,
/// so the CLI does not try to replace it. Returns the first real request it
/// receives and responds to every request with a success envelope.
fn serve_one(home: &TempDir) -> std::thread::JoinHandle<Value> {
    let sockets = home.path().join("s");
    std::fs::create_dir_all(&sockets).unwrap();
    std::fs::write(
        sockets.join(format!("{SESSION}.version")),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    let listener = UnixListener::bind(sockets.join(format!("{SESSION}.sock"))).unwrap();
    std::thread::spawn(move || loop {
        let (mut stream, _) = listener.accept().unwrap();
        // Probe connections close without sending a line; skip them.
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        if line.is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line).unwrap();
        let id = request["id"].clone();
        let response = serde_json::json!({"id": id, "success": true, "data": {}});
        stream
            .write_all(format!("{response}\n").as_bytes())
            .unwrap();
        // The CLI may first ask an unversioned fake daemon to shut down.
        if request["action"] != "__agent_browser_internal_shutdown" {
            return request;
        }
    })
}

#[test]
fn valid_page_headers_reach_the_daemon_unchanged() {
    let home = TempDir::new().unwrap();
    let server = serve_one(&home);
    let output = command(&home)
        .args([
            "--json",
            "open",
            "http://127.0.0.1:9/test",
            "--headers",
            r#"{"Authorization":"Bearer t"}"#,
        ])
        .output()
        .unwrap();
    let request = server.join().unwrap();
    assert_eq!(request["action"], "navigate", "{request}");
    assert_eq!(request["headers"]["Authorization"], "Bearer t", "{request}");
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn set_headers_with_string_values_still_forwards() {
    let home = TempDir::new().unwrap();
    let server = serve_one(&home);
    let _ = command(&home)
        .args(["set", "headers", r#"{"a":"b"}"#])
        .output()
        .unwrap();
    let request = server.join().unwrap();
    assert_eq!(request["action"], "headers", "{request}");
    assert_eq!(request["headers"]["a"], "b", "{request}");
}
