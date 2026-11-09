//! Decides whether a shell command is safe to approve: every command inside it,
//! including loop and branch bodies, heredoc consumers and `$(...)`, must match
//! an allow rule. Anything the walker does not understand makes it pass.

use crate::rules::Rules;
use tree_sitter::{Node, Parser};

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Approve the call without the classifier.
    Allow,
    /// Stay silent; Claude Code's own flow decides. The string says why.
    Pass(String),
}

type R = Result<(), String>;

/// Constructs that Claude Code's built-in rule matching never approves.
/// Without one of them the hook stays silent and native matching decides.
const GAP_KINDS: &[&str] = &[
    "for_statement", "while_statement", "if_statement", "case_statement", "compound_statement",
    "subshell", "negated_command", "variable_assignment", "variable_assignments",
    "declaration_command", "unset_command", "test_command", "heredoc_redirect",
    "herestring_redirect", "function_definition",
];

/// zsh and bash call these functions on their own (hooks, traps, fallbacks).
const HOOK_FUNCTIONS: &[&str] = &[
    "command_not_found_handler", "command_not_found_handle", "precmd", "preexec", "chpwd",
    "periodic", "zshexit", "zshaddhistory", "zsh_directory_name",
];

const SAFE_BUILTINS: &[&str] = &["true", "false", ":", "break", "continue", "shift", "exit", "return"];
const FIND_EXEC: &[&str] = &[
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls",
];
const ARITH_OPS: &[&str] = &["-eq", "-ne", "-lt", "-le", "-gt", "-ge"];

/// Environment variables allowed in `export X=` and `X=v cmd` forms.
const ENV_SAFE: &[&str] = &[
    "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_NUMERIC", "LC_TIME", "LC_MESSAGES", "LANG", "LANGUAGE",
    "TZ", "NO_COLOR", "FORCE_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "COLUMNS", "LINES", "TERM",
    "GREP_COLOR", "GREP_COLORS",
];

/// Shell variables with special meaning in bash or zsh (tied arrays, prompts,
/// hook arrays, zsh/parameter and zsh/mapfile specials).
const SPECIAL_VARS: &[&str] = &[
    "_", "PATH", "path", "FPATH", "fpath", "CDPATH", "cdpath", "MANPATH", "manpath", "MODULE_PATH",
    "module_path", "MAILPATH", "mailpath", "MAILCHECK", "MAIL", "PSVAR", "psvar", "IFS", "PS1",
    "PS2", "PS3", "PS4", "PROMPT", "PROMPT2", "PROMPT3", "PROMPT4", "RPROMPT", "RPROMPT2", "RPS1",
    "RPS2", "prompt", "PROMPT_COMMAND", "ENV", "BASH_ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS",
    "HOME", "SHELL", "TMOUT", "READNULLCMD", "NULLCMD", "HISTFILE", "HISTCMD", "histchars",
    "PERIOD", "POSTEDIT", "GLOBIGNORE", "FIGNORE", "fignore", "OPTIND", "OPTARG", "TMPPREFIX",
    "TMPDIR", "WORDCHARS", "watch", "argv", "status", "pipestatus", "options", "aliases",
    "galiases", "saliases", "functions", "commands", "builtins", "reswords", "nameddirs",
    "userdirs", "modules", "parameters", "history", "historywords", "jobtexts", "jobdirs",
    "jobstates", "funcstack", "funcfiletrace", "funcsourcetrace", "functrace", "widgets",
    "keymaps", "patchars", "termcap", "terminfo", "errnos", "sysparams", "mapfile", "dis_aliases",
    "dis_galiases", "dis_saliases", "dis_functions", "dis_builtins", "dis_reswords",
    "dis_patchars", "signals",
];
const SPECIAL_PREFIXES: &[&str] = &[
    "LD_", "DYLD_", "BASH_", "ZSH_", "GIT_", "PYTHON", "NODE_", "PERL", "RUBY", "LESS", "npm_",
];

/// `env_get` returns an environment variable as the shell sees it
/// (the hook inherits Claude Code's environment, which the Bash tool shell shares).
pub fn analyze(cmd: &str, rules: &Rules, env_get: &dyn Fn(&str) -> Option<String>) -> Verdict {
    if cmd.len() > 10_000 {
        return Verdict::Pass("command longer than 10000 chars".into());
    }
    let mut parser = Parser::new();
    if parser.set_language(&tree_sitter_bash::LANGUAGE.into()).is_err() {
        return Verdict::Pass("parser init failed".into());
    }
    let Some(mut tree) = parser.parse(cmd, None) else {
        return Verdict::Pass("parse failed".into());
    };
    let mut src = cmd.to_string();
    if tree.root_node().has_error() {
        // tree-sitter-bash fails on `cmd <<'EOF' 2>&1 | ...`; bash does not.
        if let Some(re) = reorder_heredoc_redirects(cmd) {
            if let Some(t) = parser.parse(&re, None).filter(|t| !t.root_node().has_error()) {
                tree = t;
                src = re;
            }
        }
    }
    let root = tree.root_node();
    if root.has_error() {
        return Verdict::Pass("parse error (or zsh-only syntax)".into());
    }
    let mut ctx = Ctx {
        src: src.as_bytes(),
        rules,
        env_get,
        tmpdir: env_get("TMPDIR").filter(|t| is_temp_dir(t)),
        gap: false,
        functions: Vec::new(),
    };
    match ctx.node(root) {
        Err(reason) => Verdict::Pass(reason),
        Ok(()) if ctx.gap => Verdict::Allow,
        Ok(()) => Verdict::Pass("no loop/branch/heredoc/assignment; native rules decide".into()),
    }
}

struct Ctx<'a> {
    src: &'a [u8],
    rules: &'a Rules,
    env_get: &'a dyn Fn(&str) -> Option<String>,
    /// `$TMPDIR` when it points into a system temp location; `TMPDIR` itself
    /// cannot be reassigned inside a command (it is a special variable here).
    tmpdir: Option<String>,
    gap: bool,
    /// Functions defined earlier in this command whose bodies passed the checks.
    functions: Vec<String>,
}

fn render(words: &[Option<String>]) -> String {
    words.iter().map(|w| w.as_deref().unwrap_or("<expr>")).collect::<Vec<_>>().join(" ")
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn is_ident(name: &str) -> bool {
    let mut it = name.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn check_env_name(name: &str) -> R {
    if ENV_SAFE.contains(&name) {
        Ok(())
    } else {
        Err(format!("exported variable not in safe list: {name}"))
    }
}

/// macOS per-user temp dirs live under /var/folders (= /private/var/folders).
fn is_temp_dir(t: &str) -> bool {
    let under = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/"];
    under.iter().any(|p| t.starts_with(p) && t.len() > p.len()) && !t.split('/').any(|s| s == "..")
}

fn set_builtin(words: &[Option<String>]) -> R {
    for w in &words[1..] {
        let w = w.as_deref().ok_or("set: non-literal argument")?;
        let flags = w.len() > 1
            && (w.starts_with('-') || w.starts_with('+'))
            && w[1..].chars().all(|c| "euxo".contains(c));
        let opt = matches!(w, "pipefail" | "errexit" | "nounset" | "xtrace" | "noclobber");
        if !flags && !opt {
            return Err(format!("set: unsupported argument {w}"));
        }
    }
    Ok(())
}

fn is_int(w: &Option<String>) -> bool {
    matches!(w, Some(s) if s.parse::<i64>().is_ok())
}

impl<'a> Ctx<'a> {
    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or("")
    }

    fn node(&mut self, n: Node) -> R {
        if n.is_error() || n.is_missing() {
            return Err("parse error".into());
        }
        if !n.is_named() {
            return anon(n);
        }
        let kind = n.kind();
        if GAP_KINDS.contains(&kind) {
            self.gap = true;
        }
        match kind {
            "program" | "list" | "pipeline" | "redirected_statement" | "comment" | "compound_statement"
            | "subshell" | "negated_command" | "if_statement" | "elif_clause" | "else_clause"
            | "while_statement" | "do_group" | "case_statement"
            | "variable_assignments" => self.children(n),
            // case patterns only match strings, they never expand to file names
            "case_item" => {
                let mut c = n.walk();
                let kids: Vec<Node> = n.children(&mut c).collect();
                kids.into_iter()
                    .filter(|k| k.kind() != "extglob_pattern")
                    .try_for_each(|k| self.node(k))
            }
            "for_statement" => {
                if let Some(v) = n.child_by_field_name("variable") {
                    self.check_plain_name(self.text(v))?;
                }
                self.children_except(n, "variable")
            }
            "command" => self.command(n),
            "function_definition" => {
                let name = n.child_by_field_name("name").map(|k| self.text(k)).unwrap_or("");
                let valid = !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
                if !valid || name.starts_with("TRAP") || HOOK_FUNCTIONS.contains(&name) {
                    return Err(format!("function name not allowed: {name}"));
                }
                self.functions.push(name.to_string());
                self.children_except(n, "name")
            }
            "variable_assignment" => self.assignment(n, false),
            "declaration_command" => self.declaration(n),
            "unset_command" => self.unset(n),
            "test_command" => self.test(n),
            "file_redirect" => self.file_redirect(n),
            "heredoc_redirect" => self.heredoc(n),
            "herestring_redirect" => self.word_children(n),
            "word" | "string" | "raw_string" | "ansi_c_string" | "concatenation" | "number"
            | "simple_expansion" | "expansion" | "command_substitution" | "brace_expression" => self.word(n),
            k => Err(format!("unsupported construct: {k}")),
        }
    }

    fn children(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        kids.into_iter().try_for_each(|k| self.node(k))
    }

    fn children_except(&mut self, n: Node, field: &str) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        for (i, k) in kids.into_iter().enumerate() {
            if n.field_name_for_child(i as u32) != Some(field) {
                self.node(k)?;
            }
        }
        Ok(())
    }

    fn word_children(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        for k in kids {
            if k.is_named() {
                self.word(k)?;
            } else {
                anon(k)?;
            }
        }
        Ok(())
    }

    /// Checks a word or a part of one: no arithmetic, no process substitution,
    /// no zsh glob qualifiers; `$(...)` bodies are checked like commands.
    fn word(&mut self, n: Node) -> R {
        if n.is_error() || n.is_missing() {
            return Err("parse error".into());
        }
        match n.kind() {
            "word" => {
                let t = self.text(n);
                if t.contains(['(', ')']) {
                    return Err(format!("word with parentheses (zsh glob qualifier?): {t}"));
                }
                Ok(())
            }
            "number" | "raw_string" | "ansi_c_string" | "string_content" | "variable_name"
            | "special_variable_name" | "heredoc_content" | "regex" => Ok(()),
            "string" | "concatenation" | "array" | "brace_expression" | "simple_expansion" => {
                self.word_children(n)
            }
            "expansion" => self.expansion(n),
            "command_substitution" => self.children(n),
            "process_substitution" => {
                self.gap = true;
                self.children(n)
            }
            k => Err(format!("unsupported word part: {k}")),
        }
    }

    fn expansion(&mut self, n: Node) -> R {
        let t = self.text(n);
        if ["${(", "${~", "${=", "${^"].iter().any(|p| t.starts_with(p)) {
            return Err(format!("zsh expansion flags: {t}"));
        }
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        for k in kids {
            if !k.is_named() {
                if k.kind() == "@" {
                    return Err(format!("${{x@op}} transformation: {t}"));
                }
                anon(k)?;
                continue;
            }
            if k.kind() == "subscript" {
                let idx = k.child_by_field_name("index").map(|i| self.text(i)).unwrap_or("");
                if idx != "@" && idx != "*" {
                    return Err(format!("array subscript is evaluated arithmetically: {t}"));
                }
                continue;
            }
            self.word(k)?;
        }
        Ok(())
    }

    fn output_target(&self, target: Option<String>) -> R {
        let t = target.ok_or("non-literal redirect target")?;
        if ["/dev/null", "/dev/stdout", "/dev/stderr"].contains(&t.as_str()) {
            return Ok(());
        }
        let mut roots = vec!["/tmp/".to_string(), "/private/tmp/".to_string()];
        if let Some(d) = &self.tmpdir {
            let d = if d.ends_with('/') { d.clone() } else { format!("{d}/") };
            match d.strip_prefix("/private") {
                Some(short) => roots.push(short.to_string()),
                None => roots.push(format!("/private{d}")),
            }
            roots.push(d);
        }
        let inside = roots.iter().any(|r| t.starts_with(r.as_str()) && t.len() > r.len());
        if inside && !t.split('/').any(|s| s == "..") {
            return Ok(());
        }
        Err(format!("redirect writes outside temp dirs: {t}"))
    }

    /// Like `literal`, but `$TMPDIR` / `${TMPDIR}` resolve to the hook's `TMPDIR`.
    fn redirect_path(&self, n: Node) -> Option<String> {
        let is_tmpdir_var = |k: Node| {
            let mut c = k.walk();
            let kids: Vec<Node> = k.children(&mut c).collect();
            let names: Vec<&str> = kids.iter().filter(|x| x.is_named()).map(|x| self.text(*x)).collect();
            let plain = kids.iter().all(|x| x.is_named() || matches!(x.kind(), "$" | "${" | "}"));
            plain && names == ["TMPDIR"]
        };
        match n.kind() {
            "simple_expansion" | "expansion" if is_tmpdir_var(n) => self.tmpdir.clone(),
            "string" | "concatenation" => {
                let mut c = n.walk();
                let mut s = String::new();
                for k in n.named_children(&mut c) {
                    let part = match k.kind() {
                        "string_content" => Some(unescape(self.text(k))),
                        _ => self.redirect_path(k),
                    };
                    s.push_str(&part?);
                }
                Some(s)
            }
            _ => self.literal(n),
        }
    }

    fn literal(&self, n: Node) -> Option<String> {
        match n.kind() {
            "word" => Some(unescape(self.text(n))),
            "number" => Some(self.text(n).to_string()),
            "raw_string" => {
                let t = self.text(n);
                Some(t.get(1..t.len().saturating_sub(1))?.to_string())
            }
            "string" => {
                let mut c = n.walk();
                let mut s = String::new();
                for k in n.named_children(&mut c) {
                    if k.kind() != "string_content" {
                        return None;
                    }
                    s.push_str(&unescape(self.text(k)));
                }
                Some(s)
            }
            "concatenation" => {
                let mut c = n.walk();
                let mut s = String::new();
                for k in n.named_children(&mut c) {
                    s.push_str(&self.literal(k)?);
                }
                Some(s)
            }
            "command_name" => self.literal(n.named_child(0)?),
            _ => None,
        }
    }

    fn command(&mut self, n: Node) -> R {
        let mut words: Vec<Option<String>> = Vec::new();
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        for (i, k) in kids.into_iter().enumerate() {
            if k.is_error() || k.is_missing() {
                return Err("parse error".into());
            }
            match (n.field_name_for_child(i as u32), k.kind()) {
                (Some("name"), _) => {
                    let inner = k.named_child(0).ok_or("empty command name")?;
                    self.word(inner)?;
                    let lit = self.literal(inner);
                    if lit.is_none() {
                        return Err(format!("non-literal command name: {}", self.text(k)));
                    }
                    words.push(lit);
                }
                (Some("argument"), _) => {
                    self.word(k)?;
                    words.push(self.literal(k));
                }
                (_, "variable_assignment") => {
                    self.gap = true;
                    self.assignment(k, true)?;
                }
                (_, "file_redirect") => self.file_redirect(k)?,
                (_, "herestring_redirect") => {
                    self.gap = true;
                    self.word_children(k)?;
                }
                (_, "heredoc_redirect") => {
                    self.gap = true;
                    self.heredoc(k)?;
                }
                (_, _) if !k.is_named() => anon(k)?,
                (_, kind) => return Err(format!("unsupported in command: {kind}")),
            }
        }
        if words.is_empty() {
            return Ok(());
        }
        self.check_words(words)
    }

    fn check_words(&mut self, mut words: Vec<Option<String>>) -> R {
        strip_wrappers(&mut words)?;
        let name = match words.first() {
            Some(Some(n)) => n.clone(),
            Some(None) => return Err("non-literal command after wrapper".into()),
            None => return Err("nothing after wrapper".into()),
        };
        if self.rules.blocks(&words) {
            return Err(format!("may match a deny/ask rule: {}", render(&words)));
        }
        if self.functions.contains(&name) {
            return Ok(());
        }
        match name.as_str() {
            n if SAFE_BUILTINS.contains(&n) => return Ok(()),
            "command" => return Ok(()), // only `command -v/-V` reaches here
            "read" => return self.read_builtin(&words),
            "set" => return set_builtin(&words),
            "test" | "[" => return test_words(&words),
            _ => {}
        }
        if name == "find" && words.iter().flatten().any(|w| FIND_EXEC.contains(&w.as_str())) {
            return Err("find with an action that runs, deletes or writes".into());
        }
        if !self.rules.allows(&words) {
            return Err(format!("not in allow rules: {}", render(&words)));
        }
        Ok(())
    }

    fn read_builtin(&mut self, words: &[Option<String>]) -> R {
        let mut i = 1;
        while i < words.len() {
            let w = words[i].as_deref().ok_or("read: non-literal argument")?;
            if w.len() > 1 && w.starts_with('-') {
                let last = w.chars().last().unwrap_or('-');
                if "adptnNui".contains(last) {
                    let v = words.get(i + 1).and_then(|x| x.as_deref()).ok_or("read: missing option value")?;
                    if last == 'a' {
                        self.check_plain_name(v)?;
                    }
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            self.check_plain_name(w)?;
            i += 1;
        }
        Ok(())
    }

    /// Plain shell variables: not special to bash/zsh and not already exported
    /// (assigning an exported name changes the environment of child processes).
    fn check_plain_name(&self, name: &str) -> R {
        if !is_ident(name) {
            return Err(format!("bad variable name: {name}"));
        }
        if SPECIAL_VARS.contains(&name)
            || SPECIAL_PREFIXES.iter().any(|p| name.starts_with(p))
            || name.ends_with("_functions")
        {
            return Err(format!("special shell variable: {name}"));
        }
        if (self.env_get)(name).is_some() {
            return Err(format!("variable exists in the environment: {name}"));
        }
        Ok(())
    }

    fn assignment(&mut self, n: Node, exported: bool) -> R {
        let name = n.child_by_field_name("name").ok_or("assignment without name")?;
        if name.kind() != "variable_name" {
            return Err(format!("subscripted assignment: {}", self.text(n)));
        }
        let name = self.text(name);
        if exported {
            check_env_name(name)?;
        } else {
            self.check_plain_name(name)?;
        }
        if let Some(v) = n.child_by_field_name("value") {
            self.word(v)?;
        }
        Ok(())
    }

    fn declaration(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        let mut exported = false;
        for k in &kids {
            if !k.is_named() {
                match k.kind() {
                    "export" => exported = true,
                    "local" | "declare" | "typeset" | "readonly" => {}
                    other => return Err(format!("unsupported declaration: {other}")),
                }
            } else if k.kind() == "word" {
                let f = self.text(*k);
                let ok = f.len() > 1
                    && (f.starts_with('-') || f.starts_with('+'))
                    && f[1..].chars().all(|ch| "aAilrugxp".contains(ch));
                if !ok {
                    return Err(format!("unsupported declaration flag: {f}"));
                }
                if f.starts_with('-') && f.contains('x') {
                    exported = true;
                }
            }
        }
        for k in kids.into_iter().filter(|k| k.is_named()) {
            match k.kind() {
                "variable_assignment" => self.assignment(k, exported)?,
                "variable_name" if exported => check_env_name(self.text(k))?,
                "variable_name" => self.check_plain_name(self.text(k))?,
                "word" => {}
                other => return Err(format!("unsupported in declaration: {other}")),
            }
        }
        Ok(())
    }

    fn unset(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.named_children(&mut c).collect();
        for k in kids {
            match k.kind() {
                "variable_name" => self.check_plain_name(self.text(k))?,
                "word" if self.text(k) == "-v" => {}
                other => return Err(format!("unsupported in unset: {other} {}", self.text(k))),
            }
        }
        Ok(())
    }

    /// `[[ ... ]]` and `[ ... ]`. Numeric comparisons evaluate operands as
    /// arithmetic (code execution through array subscripts), so they must be literal.
    fn test(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        let arith = kids.iter().any(|k| ARITH_OPS.contains(&self.text(*k)));
        for k in kids {
            if !k.is_named() {
                anon(k)?;
                continue;
            }
            match k.kind() {
                "test_operator" => {}
                "binary_expression" | "unary_expression" | "parenthesized_expression" => self.test(k)?,
                "number" => {}
                _ if arith => {
                    if self.literal(k).and_then(|s| s.parse::<i64>().ok()).is_none() {
                        return Err(format!("numeric test on non-literal operand: {}", self.text(n)));
                    }
                }
                "extglob_pattern" => return Err("extglob pattern".into()),
                _ => self.word(k)?,
            }
        }
        Ok(())
    }

    fn file_redirect(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        let mut op: Option<&str> = None;
        let mut dest: Vec<Node> = Vec::new();
        for (i, k) in kids.into_iter().enumerate() {
            match n.field_name_for_child(i as u32) {
                Some("destination") => dest.push(k),
                Some("descriptor") => {}
                _ if !k.is_named() => op = Some(k.kind()),
                _ => return Err(format!("unsupported in redirect: {}", k.kind())),
            }
        }
        for d in &dest {
            self.word(*d)?;
        }
        let target = if dest.len() == 1 { self.redirect_path(dest[0]) } else { None };
        match op.ok_or("redirect without operator")? {
            "<" => Ok(()),
            ">&" | "<&" if matches!(&target, Some(t) if t == "-" || t.chars().all(|ch| ch.is_ascii_digit())) => Ok(()),
            ">" | ">>" | ">|" | "&>" | "&>>" | ">&" => self.output_target(target),
            other => Err(format!("unsupported redirect: {other}")),
        }
    }

    fn heredoc(&mut self, n: Node) -> R {
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        for k in kids {
            if !k.is_named() {
                anon(k)?;
                continue;
            }
            match k.kind() {
                "heredoc_start" | "heredoc_end" => {}
                "heredoc_body" => {
                    let mut c2 = k.walk();
                    let parts: Vec<Node> = k.named_children(&mut c2).collect();
                    for p in parts {
                        self.word(p)?;
                    }
                }
                _ => self.node(k)?,
            }
        }
        Ok(())
    }
}

fn anon(n: Node) -> R {
    match n.kind() {
        "&" => Err("background job (&)".into()),
        "coproc" => Err("coproc".into()),
        _ => Ok(()),
    }
}

fn test_words(words: &[Option<String>]) -> R {
    for (i, w) in words.iter().enumerate() {
        if matches!(w, Some(s) if ARITH_OPS.contains(&s.as_str())) {
            let ok = i > 0 && is_int(&words[i - 1]) && words.get(i + 1).is_some_and(is_int);
            if !ok {
                return Err("numeric test on non-literal operand".into());
            }
        }
    }
    Ok(())
}

/// Drops the wrappers Claude Code itself strips before matching rules.
fn strip_wrappers(words: &mut Vec<Option<String>>) -> R {
    let lit = |w: &Vec<Option<String>>, i: usize| w.get(i).cloned().flatten();
    loop {
        let Some(head) = lit(words, 0) else { return Ok(()) };
        match head.as_str() {
            "timeout" => {
                words.remove(0);
                while let Some(w) = lit(words, 0).filter(|w| w.starts_with('-')) {
                    words.remove(0);
                    if matches!(w.as_str(), "-s" | "-k" | "--signal" | "--kill-after") && !words.is_empty() {
                        words.remove(0);
                    }
                }
                if lit(words, 0).is_none() {
                    return Err("timeout without a literal duration".into());
                }
                words.remove(0);
            }
            "time" | "nohup" | "builtin" | "noglob" => {
                words.remove(0);
                if head == "time" && lit(words, 0).as_deref() == Some("-p") {
                    words.remove(0);
                }
            }
            "nice" => {
                words.remove(0);
                match lit(words, 0).as_deref() {
                    Some("-n") => {
                        words.drain(..words.len().min(2));
                    }
                    Some(w) if w.starts_with('-') => {
                        words.remove(0);
                    }
                    _ => {}
                }
            }
            "stdbuf" => {
                words.remove(0);
                while let Some(w) = lit(words, 0).filter(|w| w.starts_with('-')) {
                    words.remove(0);
                    if matches!(w.as_str(), "-i" | "-o" | "-e") && !words.is_empty() {
                        words.remove(0);
                    }
                }
            }
            "command" => {
                if matches!(lit(words, 1).as_deref(), Some("-v" | "-V")) {
                    words.truncate(1);
                    return Ok(());
                }
                words.remove(0);
                if lit(words, 0).as_deref() == Some("-p") {
                    words.remove(0);
                }
            }
            "xargs" => match lit(words, 1) {
                Some(w) if !w.starts_with('-') => {
                    words.remove(0);
                }
                _ => return Ok(()),
            },
            _ => return Ok(()),
        }
    }
}

/// Moves stdout/stderr redirects that directly follow a heredoc operator in
/// front of it: `cmd <<'EOF' 2>&1 | x` becomes `cmd 2>&1 <<'EOF' | x`. The moved
/// redirects never touch fd 0, so the meaning is unchanged. Returns None when
/// nothing moved.
pub fn reorder_heredoc_redirects(cmd: &str) -> Option<String> {
    let mut changed = false;
    let lines: Vec<String> = cmd.split('\n').map(|l| reorder_line(l, &mut changed)).collect();
    changed.then(|| lines.join("\n"))
}

fn reorder_line(line: &str, changed: &mut bool) -> String {
    let b = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let (mut i, mut last) = (0, 0);
    while i + 1 < b.len() {
        let is_op = b[i] == b'<' && b[i + 1] == b'<' && b.get(i + 2) != Some(&b'<') && (i == 0 || b[i - 1] != b'<');
        if !is_op {
            i += 1;
            continue;
        }
        let mut j = i + 2;
        if b.get(j) == Some(&b'-') {
            j += 1;
        }
        while b.get(j) == Some(&b' ') {
            j += 1;
        }
        let Some(hd_end) = heredoc_delim_end(b, j) else {
            i += 2;
            continue;
        };
        let mut red_end = hd_end;
        loop {
            let mut m = red_end;
            while b.get(m) == Some(&b' ') {
                m += 1;
            }
            match out_redirect_end(b, m) {
                Some(e) => red_end = e,
                None => break,
            }
        }
        if red_end > hd_end {
            out.push_str(&line[last..i]);
            out.push_str(line[hd_end..red_end].trim_start());
            out.push(' ');
            out.push_str(&line[i..hd_end]);
            last = red_end;
            *changed = true;
        }
        i = red_end.max(hd_end);
    }
    out.push_str(&line[last..]);
    out
}

fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn heredoc_delim_end(b: &[u8], j: usize) -> Option<usize> {
    let q = *b.get(j)?;
    if q == b'\'' || q == b'"' {
        let mut k = j + 1;
        while k < b.len() && is_word_byte(b[k]) {
            k += 1;
        }
        return (k > j + 1 && b.get(k) == Some(&q)).then_some(k + 1);
    }
    let mut k = j;
    while k < b.len() && is_word_byte(b[k]) {
        k += 1;
    }
    (k > j).then_some(k)
}

/// End of a `>file`, `2>&1`, `&>file` style redirect starting at `m` (fd 1/2 only).
fn out_redirect_end(b: &[u8], m: usize) -> Option<usize> {
    let mut p = m;
    let both = b.get(p) == Some(&b'&');
    if both {
        p += 1;
    } else if matches!(b.get(p), Some(b'1' | b'2')) {
        p += 1;
    }
    if b.get(p) != Some(&b'>') {
        return None;
    }
    p += 1;
    if b.get(p) == Some(&b'>') {
        p += 1;
    }
    let boundary = |p: usize| matches!(b.get(p), None | Some(b' ' | b'|' | b';'));
    if !both && b.get(p) == Some(&b'&') {
        p += 1;
        if !matches!(b.get(p), Some(b'1' | b'2' | b'-')) {
            return None;
        }
        p += 1;
        return boundary(p).then_some(p);
    }
    while b.get(p) == Some(&b' ') {
        p += 1;
    }
    let start = p;
    while p < b.len() && !b" |;&<>()'\"`$\\".contains(&b[p]) {
        p += 1;
    }
    (p > start && boundary(p)).then_some(p)
}
