//! Bash allow/deny/ask rules read from Claude Code settings files.

use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone)]
enum Pat {
    /// `Bash(arc status *)`: the first words match, anything may follow.
    Prefix(Vec<String>),
    /// `Bash(pwd)`: the whole command matches.
    Exact(Vec<String>),
}

/// Rules mirrored from `permissions` in Claude Code settings.
#[derive(Debug, Default)]
pub struct Rules {
    allow: Vec<Pat>,
    /// deny + ask rules as word prefixes; the last word may be partial.
    block: Vec<Vec<String>>,
    block_all: bool,
}

/// Rules that auto mode drops because they grant arbitrary code execution.
const DROPPED_HEADS: &[&str] = &[
    "bash", "sh", "zsh", "dash", "ksh", "fish", "node", "nodejs", "deno", "bun", "perl", "ruby",
    "php", "lua", "osascript", "pwsh", "powershell", "tclsh", "Rscript", "eval", "exec", "sudo",
    "env", "xargs", "npx", "uv", "uvx", "pipx", "source", ".",
];
const PACKAGE_MANAGERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];

fn is_dropped(tokens: &[String]) -> bool {
    let head = tokens[0].as_str();
    if DROPPED_HEADS.contains(&head) {
        return true;
    }
    let py = head.strip_prefix("python").map(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if py == Some(true) {
        return true;
    }
    if PACKAGE_MANAGERS.contains(&head) {
        return tokens.len() == 1 || matches!(tokens[1].as_str(), "run" | "exec" | "x" | "dlx");
    }
    false
}

fn bash_inner(rule: &str) -> Option<&str> {
    if rule == "Bash" {
        return Some("");
    }
    rule.strip_prefix("Bash(")?.strip_suffix(')')
}

impl Rules {
    pub fn from_lists(allow: &[&str], block: &[&str]) -> Self {
        let mut r = Rules::default();
        allow.iter().for_each(|s| r.add_allow(s));
        block.iter().for_each(|s| r.add_block(s));
        r
    }

    /// Loads `settings.json` and `settings.local.json` from `$CLAUDE_CONFIG_DIR` or `~/.claude`.
    pub fn load() -> Self {
        let dir = std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude")));
        let mut r = Rules::default();
        let Some(dir) = dir else { return r };
        for name in ["settings.json", "settings.local.json"] {
            let Ok(text) = std::fs::read_to_string(dir.join(name)) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
            let perms = &v["permissions"];
            for s in perms["allow"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                r.add_allow(s);
            }
            for key in ["deny", "ask"] {
                for s in perms[key].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    r.add_block(s);
                }
            }
        }
        r
    }

    fn add_allow(&mut self, rule: &str) {
        let Some(inner) = bash_inner(rule.trim()) else { return };
        let inner = inner.trim();
        if inner.is_empty() || inner.contains(['"', '\'', '\\']) {
            return;
        }
        let (body, prefix) = match inner.strip_suffix(" *").or_else(|| inner.strip_suffix(":*")) {
            Some(b) => (b, true),
            None => (inner, false),
        };
        if body.contains('*') {
            return; // wildcards elsewhere are not emulated
        }
        let tokens: Vec<String> = body.split_whitespace().map(String::from).collect();
        if tokens.is_empty() || is_dropped(&tokens) {
            return;
        }
        self.allow.push(if prefix { Pat::Prefix(tokens) } else { Pat::Exact(tokens) });
    }

    fn add_block(&mut self, rule: &str) {
        let Some(inner) = bash_inner(rule.trim()) else { return };
        let mut text = inner.trim();
        if let Some(i) = text.find('*') {
            text = &text[..i];
        }
        let text = text.trim_end().trim_end_matches(':');
        let tokens: Vec<String> = text.split_whitespace().map(String::from).collect();
        if tokens.is_empty() {
            self.block_all = true;
        } else {
            self.block.push(tokens);
        }
    }

    /// True when the words match an allow rule. `None` is a word with expansions.
    pub fn allows(&self, words: &[Option<String>]) -> bool {
        let eq = |toks: &[String]| toks.iter().zip(words).all(|(t, w)| w.as_deref() == Some(t.as_str()));
        self.allow.iter().any(|p| match p {
            Pat::Prefix(t) => words.len() >= t.len() && eq(t),
            Pat::Exact(t) => words.len() == t.len() && eq(t),
        })
    }

    /// True when the words may match a deny or ask rule. Unknown words count as a match.
    pub fn blocks(&self, words: &[Option<String>]) -> bool {
        if self.block_all {
            return true;
        }
        self.block.iter().any(|toks| {
            if words.len() < toks.len() {
                return false;
            }
            toks.iter().enumerate().all(|(i, t)| match &words[i] {
                None => true,
                Some(w) if i + 1 == toks.len() => w.starts_with(t.as_str()),
                Some(w) => w == t,
            })
        })
    }
}
