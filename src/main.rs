//! Claude Code PreToolUse hook. Reads the hook JSON from stdin and prints an
//! `allow` decision only when every command inside a Bash call matches the
//! user's allow rules; otherwise prints nothing and the normal flow decides.
//!
//! `bash-allow-hook explain` reads a raw command from stdin and prints the verdict.

use bash_allow_hook::{Rules, Verdict, analyze};
use serde_json::{Value, json};
use std::io::Read;

fn env_get(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let explain = std::env::args().nth(1).as_deref() == Some("explain");
    let _ = std::panic::catch_unwind(|| if explain { run_explain() } else { run_hook() });
}

fn run_explain() {
    let mut cmd = String::new();
    let _ = std::io::stdin().read_to_string(&mut cmd);
    let cmd = cmd.strip_suffix('\n').unwrap_or(&cmd);
    match analyze(cmd, &Rules::load(), &env_get) {
        Verdict::Allow => println!("ALLOW"),
        Verdict::Pass(why) => println!("PASS: {why}"),
    }
}

fn run_hook() {
    if std::env::var_os("BASH_ALLOW_HOOK_DISABLE").is_some() {
        return;
    }
    let mut input = String::new();
    if std::io::stdin().take(4 << 20).read_to_string(&mut input).is_err() {
        return;
    }
    let Ok(v) = serde_json::from_str::<Value>(&input) else { return };
    if v["tool_name"] != "Bash" || v["permission_mode"] == "plan" {
        return;
    }
    let Some(cmd) = v["tool_input"]["command"].as_str() else { return };
    if analyze(cmd, &Rules::load(), &env_get) == Verdict::Allow {
        let out = json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "bash-allow-hook: every command matches allow rules",
        }});
        println!("{out}");
    }
}
