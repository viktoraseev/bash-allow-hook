# bash-allow-hook

A Claude Code PreToolUse hook for Bash. It approves commands that use `for`/`while`/`if`/`case`,
heredocs, variable assignments, functions and subshells when **every** command inside matches
the allow rules in `~/.claude/settings.json`. Claude Code's built-in rules never approve such
constructs, so in auto mode they always go to the classifier.

For anything else the hook stays silent and the normal flow decides: native rules or the classifier.
The hook never answers `deny` or `ask`.

## How it decides

1. Parses the command with tree-sitter-bash and stays silent on a parse error.
   It also stays silent on zsh-only syntax: `*(e:…:)`, `=(…)`, `${(e)x}`.
2. Walks the tree: loop and branch bodies, `$(...)`, `<(...)`, heredoc consumers, functions.
3. Strips from each command the same wrappers Claude Code strips
   (`timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, bare `xargs`)
   and checks it against the allow rules. `Bash(x *)` is a prefix match, `Bash(x)` is an exact match.
   Rules that auto mode drops (`Bash(*)`, interpreters, `npm run`) are ignored.
   If a command could match a deny or ask rule, the hook stays silent.
4. Returns `allow` only when everything passes and the command contains at least one such
   construct. Simple commands are left to the native rules.

The hook stays silent on:

- arithmetic `$((…))`, `((…))`, array subscripts and `${x@P}`: substitutions inside them
  execute code;
- `-eq`/`-lt`/… with non-literal operands;
- assignments to special bash/zsh variables (`PATH`/`path`, `IFS`, `PS4`, `*_functions`,
  `aliases`, `commands`, `mapfile`, …) and to variables that already exist in the environment;
- `export` and prefix `X=v cmd` for anything except `LC_*`, `LANG`, `TZ` and similar;
- `&` (background jobs), `coproc`, `find -exec/-delete`, non-literal command names;
- zsh and bash hook functions (`TRAP*`, `chpwd`, `precmd`, `command_not_found_handler`, …);
- `>` redirects to anything other than `/dev/null`, `/tmp`, `/private/tmp` and `$TMPDIR`
  (a literal path or `"$TMPDIR/…"`; the value comes from the hook's environment and is used
  only if it points into `/var/folders` or `/tmp`).

## Install

```sh
cargo install --path .
```

`~/.claude/settings.json`:

```json
"hooks": {
  "PreToolUse": [
    { "matcher": "Bash",
      "hooks": [{ "type": "command", "command": "~/.cargo/bin/bash-allow-hook", "timeout": 5 }] }
  ]
}
```

To disable it without editing settings, set the environment variable `BASH_ALLOW_HOOK_DISABLE=1`.

## Debugging

```sh
printf '%s' 'for f in a b; do grep x "$f"; done' | bash-allow-hook explain   # ALLOW or PASS: reason
cargo run --example dump <<< 'cmd'                                          # parse tree
cargo test
```

In the session transcript, calls approved by the hook have `permissionDecision.reasonType = "hook"`.

## License

[MIT](LICENSE)
