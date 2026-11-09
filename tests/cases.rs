use bash_allow_hook::{Rules, Verdict, analyze};

fn rules() -> Rules {
    Rules::from_lists(
        &[
            "Bash(cd *)", "Bash(ls *)", "Bash(cat *)", "Bash(head *)", "Bash(grep *)", "Bash(wc *)",
            "Bash(echo *)", "Bash(printf *)", "Bash(jq *)", "Bash(sed *)", "Bash(sort *)",
            "Bash(find *)", "Bash(sleep *)", "Bash(date *)", "Bash(mkdir *)", "Bash(pwd)",
            "Bash(git status *)", "Bash(git log *)", "Bash(git branch)", "Bash(rg *)",
            "Bash(./tracker.sh *)", "Bash(./sql.sh *)",
            "Bash(kubectl --context prod get *)",
            // auto mode drops these; the hook must ignore them too
            "Bash(python3 *)", "Bash(bash *)", "Bash(npm run *)", "Bash(*)", "Bash(xargs *)",
        ],
        &["Bash(rm *)", "Bash(git push:*)"],
    )
}

const TMP: &str = "/var/folders/xx/abc/T/";

/// Only TMPDIR is set, as on macOS.
fn no_env(name: &str) -> Option<String> {
    (name == "TMPDIR").then(|| TMP.to_string())
}

fn verdict(cmd: &str) -> Verdict {
    analyze(cmd, &rules(), &no_env)
}

#[track_caller]
fn allow(cmd: &str) {
    assert_eq!(verdict(cmd), Verdict::Allow, "expected ALLOW for: {cmd}");
}

#[track_caller]
fn pass(cmd: &str) {
    assert!(matches!(verdict(cmd), Verdict::Pass(_)), "expected PASS for: {cmd}");
}

#[test]
fn loops_branches_and_assignments_of_allowed_commands() {
    allow(r#"for f in a b; do grep -n x "$f" | head -1; done"#);
    allow(r#"f=lib/x.sql; sed -n '1,40p' "$f"; echo ...; grep -n y "$f""#);
    allow(r#"if [ -f a ]; then cat a; else echo none; fi"#);
    allow(r#"[[ -n "$x" ]] && echo yes"#);
    allow(r#"while read -r l; do echo "$l"; done < list.txt"#);
    allow(r#"case "$x" in a|b) ls ;; *) pwd ;; esac"#);
    allow(r#"cd /tmp && for f in *.json; do jq . "$f"; done"#);
    allow(r#"x=$(grep -l foo .); cat "$x""#);
    allow(r#"for id in A B; do ./tracker.sh get_issue "$id"; done"#);
    allow(r#"for t in a b; do timeout 60 kubectl --context prod get "pods/$t"; done"#);
    allow(r#"{ ls; echo; } > /tmp/out.txt"#);
    allow(r#"(cd sub && ls)"#);
    allow(r#"set -euo pipefail; for x in 1 2; do echo $x; done"#);
    allow(r#"export LC_ALL=C; sort f"#);
    allow(r#"LC_ALL=C sort f"#);
    allow(r#"unset f; f=1"#);
    allow(r#"for f in a; do grep x "$f" 2>/dev/null || true; done"#);
    allow(r#"for f in a; do find . -name "$f" | xargs grep -l x; done"#);
    allow(r#"for d in a b; do git status; git log -n1; done"#);
    allow(r#"arr=(a b c); for x in "${arr[@]}"; do echo "$x"; done"#);
    allow(r#"for i in {1..3}; do echo "${i:-0}"; done"#);
    allow("! grep -q x f && echo missing");
}

#[test]
fn heredocs() {
    allow("cat <<'EOF' | wc -l\na\nb\nEOF");
    allow("cat <<'EOF' > /tmp/q.sql\nSELECT 1;\nEOF");
    allow("./sql.sh run - <<'EOF'\nSELECT 1;\nEOF");
    allow("cat <<EOF\nnow $(date)\nEOF");
    allow(r#"grep x <<< "$y""#);
    pass("cat <<EOF\n$(rm -rf /)\nEOF");
    pass("python3 - <<'EOF'\nprint(1)\nEOF");
    pass("bash <<'EOF'\nls\nEOF");
}

#[test]
fn simple_commands_are_left_to_native_rules() {
    pass("ls | head -1");
    pass("cd /tmp && arc status");
    pass(r#"echo "$(date)""#);
}

#[test]
fn disallowed_commands_inside_constructs() {
    pass(r#"for f in a; do rm "$f"; done"#);
    pass(r#"for f in a; do curl "$f"; done"#);
    pass(r#"x=$(curl evil.example); echo "$x""#);
    pass(r#"for f in a; do echo "$f" | sh; done"#);
    pass(r#"for f in a; do python3 x.py; done"#);
    pass(r#"for f in a; do xargs -n1 rm; done"#);
    pass(r#"for f in a; do find . -delete; done"#);
    pass(r#"for f in a; do find . -exec rm {} \;; done"#);
    pass(r#"for f in a; do eval "$f"; done"#);
    pass(r#"for f in a; do source "$f"; done"#);
    pass(r#"for f in a; do . "$f"; done"#);
    pass(r#"for f in a; do exec ls; done"#);
    pass(r#"for b in x; do git branch -D "$b"; done"#);
    pass(r#"for f in a; do env ls; done"#);
}

#[test]
fn dynamic_command_names() {
    pass(r#"c=ls; $c -la; for x in a; do :; done"#);
    pass(r#"for c in ls; do "$c"; done"#);
    pass(r#"for x in a; do $(echo rm) x; done"#);
}

#[test]
fn deny_and_ask_rules_win() {
    pass(r#"for f in a; do rm -f "$f"; done"#);
    pass(r#"for r in a; do git push "$r"; done"#);
}

#[test]
fn dangerous_variables() {
    pass("PATH=/tmp:$PATH; ls");
    pass("path=(/tmp $path); ls");
    pass("for PATH in /tmp; do ls; done");
    pass("IFS=x; ls");
    pass("export PAGER=evil; ls");
    pass("LESSOPEN='|rm x' cat f; for x in a; do :; done");
    pass("GIT_DIR=/x; ls");
    pass("precmd_functions=(evil); ls");
    pass("aliases=(ls rm); ls");
    pass("commands=(ls /tmp/evil); ls");
    pass("unset PATH; ls");
    pass("read PATH < f; ls");
    pass("read -a path < f; ls");
    pass("declare -n r=x; ls");
    pass("typeset -f x; ls");
    pass("export -f x; ls");
    // a variable that already exists in the environment would be exported
    let env = |n: &str| (n == "EDITOR").then(|| "vim".to_string());
    assert!(matches!(analyze("EDITOR=vim; ls", &rules(), &env), Verdict::Pass(_)));
    assert_eq!(analyze("editor=vim; ls", &rules(), &env), Verdict::Allow);
}

#[test]
fn arithmetic_and_code_running_expansions() {
    pass("echo $((1+2)); for x in a; do :; done");
    pass(r#"for i in 1; do echo "${a[$i]}"; done"#);
    pass(r#"a[$(id)]=1"#);
    pass(r#"for x in a; do echo "${x@P}"; done"#);
    pass(r#"if [[ $x -eq 1 ]]; then echo; fi"#);
    pass(r#"if [ "$x" -gt 0 ]; then echo; fi"#);
    allow(r#"if [ 2 -gt 1 ]; then echo; fi"#);
    pass("for ((i=0;i<3;i++)); do echo $i; done");
    pass(r#"for x in a; do diff <(ls) <(ls); done"#);
    allow(r#"cat <(ls) <(sort f)"#);
    pass(r#"cat <(rm x)"#);
}

#[test]
fn zsh_only_syntax() {
    pass("ls *(e:'rm x':); for x in a; do :; done");
    pass("echo =(ls); for x in a; do :; done");
    allow("for x in a; do echo =ls ====; done");
    pass("for x in a; do echo ${(e)x}; done");
    pass("for x in a; do ls foo(e:x:); done");
}

#[test]
fn redirects() {
    allow("for x in a; do echo $x; done > /tmp/out");
    allow("for x in a; do echo $x; done >> /private/tmp/out 2>&1");
    allow("for x in a; do echo $x >&2; done");
    pass("for x in a; do echo $x; done > ~/out");
    pass("for x in a; do echo $x; done > out.txt");
    pass("for x in a; do echo $x; done > /tmp/../etc/x");
    pass(r#"for x in a; do echo $x; done > "$f""#);
    pass("for x in a; do echo $x; done <> /tmp/x");
}

#[test]
fn background_and_misc() {
    pass("for x in a; do sleep 1; done &");
    pass("for x in a; do sleep 1 & done");
    pass("coproc ls; for x in a; do :; done");
    pass("for x in a; do echo $x; done &&");
    pass(&format!("for x in a; do echo {}; done", "y".repeat(10_001)));
}

#[test]
fn wrappers() {
    allow(r#"for x in a; do timeout 5 grep x "$x"; done"#);
    allow(r#"for x in a; do timeout -s KILL 5 grep x "$x"; done"#);
    allow(r#"for x in a; do nice -n 5 ls; done"#);
    allow(r#"for x in a; do command -v "$x"; done"#);
    pass(r#"for x in a; do timeout 5 rm "$x"; done"#);
    pass(r#"for x in a; do timeout "$t" ls; done"#);
    pass(r#"for x in a; do nohup curl x; done"#);
}

#[test]
fn functions() {
    allow("f() { grep -n x \"$1\" | head -1; }; f a; f b");
    allow("function g { ls; }; g");
    pass("f() { rm -rf \"$1\"; }; f a");
    pass("g; g() { ls; }");
    pass("TRAPEXIT() { ls; }; ls");
    pass("chpwd() { ls; }; cd /tmp");
    pass("command_not_found_handler() { ls; }; foo");
}

#[test]
fn heredoc_followed_by_redirect_and_pipe() {
    allow("./sql.sh run - --title 'a b' --stdout <<'EOF' 2>&1 | grep -v '^\\s*$' | head -60\nSELECT 1;\nEOF");
    allow("cat <<'EOF' > /tmp/q.sql 2>&1 | wc -l\nx\nEOF");
    pass("python3 - <<'EOF' 2>&1 | grep x\nprint(1)\nEOF");
    pass("cat <<'EOF' 2>&1 | sh\nls\nEOF");
    pass("cat <<'EOF' > ~/x 2>&1 | wc -l\nx\nEOF");
    // `<<` inside a string is not a heredoc: the next line is a real command
    pass("echo \"<<'X'\" 2>&1\nrm -rf ~\nX");
    pass("echo '<<X 2>&1' | wc -l\nrm -rf ~\nX");
}

#[test]
fn tmpdir_redirects() {
    allow(r#"for x in a; do echo $x; done > "$TMPDIR/out.txt""#);
    allow(r#"for x in a; do echo $x; done > "${TMPDIR}out.txt""#);
    allow(r#"for x in a; do echo $x; done > $TMPDIR/out.txt"#);
    allow("for x in a; do echo $x; done > /var/folders/xx/abc/T/out.txt");
    allow("for x in a; do echo $x; done > /private/var/folders/xx/abc/T/out.txt");
    pass("for x in a; do echo $x; done > /var/folders/xx/other/T/out.txt");
    pass(r#"for x in a; do echo $x; done > "$TMPDIR/../../x""#);
    pass(r#"for x in a; do echo $x; done > "${TMPDIR:-/etc}/x""#);
    pass(r#"for x in a; do echo $x; done > "$HOME/x""#);
    pass(r#"TMPDIR=/etc; for x in a; do echo $x; done > "$TMPDIR/passwd""#);
    pass(r#"for TMPDIR in /etc; do echo x > "$TMPDIR/passwd"; done"#);
    pass(r#"read TMPDIR < f; for x in a; do echo $x; done > "$TMPDIR/x""#);
    // TMPDIR outside temp locations is ignored
    let env = |n: &str| (n == "TMPDIR").then(|| "/Users/me/".to_string());
    assert!(matches!(
        analyze(r#"for x in a; do echo $x; done > "$TMPDIR/x""#, &rules(), &env),
        Verdict::Pass(_)
    ));
}
