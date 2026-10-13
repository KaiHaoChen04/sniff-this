# AGENTS.md

Rust packet sniffer with an FLTK GUI. Single crate (`edition 2024`), three deps: `fltk` (+ `fltk-theme`) for the UI, `pnet` for capture.

## Build / run

- `cargo build --bin data_link_gui` — compile (note: fltk-sys compiles FLTK via cmake on first build; slow the first time).
- The real application is the **binary target** `data_link_gui`, not the default `main`:

  ```sh
  cargo run --bin data_link_gui
  ```

- `src/main.rs` is an untouched "Hello, world!" stub. Plain `cargo run` runs it and is NOT the app. Do not mistake `src/bin/data_link_gui.rs` for a module of `main.rs` — `src/bin/` holds a separate auto-discovered binary target.
- No tests, no CI, no lints configured. Verify with `cargo build --bin data_link_gui` (or `cargo clippy --bin data_link_gui` if available).

## Gotchas

- **Requires elevated privileges** to open the raw Layer2 socket (`pnet::datalink::channel` with `ChannelType::Layer2`). Run with `sudo` (or add the capability); otherwise channel creation fails and the error is printed via eprintln. The LAN-IP popup (`modules/list.rs`, shells to `arp -a`, parses `?(IP)` tokens, RFC1918-only) works unprivileged.
- Stale sudo artifacts: if a build fails with `Permission denied` on `target/debug/.fingerprint/sniff-this-*`, those dirs are root-owned from a past `sudo` run — rebuild with `CARGO_TARGET_DIR=<tmpdir> cargo build --bin data_link_gui` instead of deleting them.
- Shared code convention: the GUI (`src/bin/`) only uses `data_link_lib` re-exports — add `pub use modules::<x>::<y>;` in `src/lib.rs` for new shared functions.
- The GUI only lists up/non-loopback interfaces; it needs at least one such interface or Start fails with "No interfaces available."
- Threading model: a capture thread is spawned per Start click, feeding a crossbeam channel back to the FLTK main loop via `app::channel`. State shared across threads (running flag, frame count, selected protocol) is wrapped in `Arc<Mutex<_>>`. Preserve this pattern when adding state — FLTK widgets must never be touched from the capture thread.
- FLTK quirks: `HoldBrowser` has no `set_text_font` — monospace rows use `@F4` per-row prefix + `set_format_char('@')` (escape `@` as `@@`); browser rows are 1-indexed (`value() - 1`); popups are a hidden `Window` shown/hidden via `show()`/`hide()` with cloned widgets moved into callbacks.
- Commit one file per commit (see `opencode.json` `git-reviewer` subagent).
