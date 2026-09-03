# AGENTS.md

Rust packet sniffer with an FLTK GUI. Single crate (`edition 2024`), three deps: `fltk` (+ `fltk-theme`) for the UI, `pnet` for capture.

## Build / run

- `cargo build` — compile (note: fltk-sys compiles FLTK via cmake on first build; slow the first time).
- The real application is the **binary target** `data_link_gui`, not the default `main`:

  ```sh
  cargo run --bin data_link_gui
  ```

- `src/main.rs` is an untouched "Hello, world!" stub. Plain `cargo run` runs it and is NOT the app. Do not mistake `src/bin/data_link_gui.rs` for a module of `main.rs` — `src/bin/` holds a separate auto-discovered binary target.

## Gotchas

- **Requires elevated privileges** to open the raw Layer2 socket (`pnet::datalink::channel` with `ChannelType::Layer2`). Run with `sudo` (or add the capability); otherwise channel creation fails and the error is printed via eprintln.
- The GUI only lists up/non-loopback interfaces; it needs at least one such interface or Start fails with "No interfaces available."
- Threading model: a capture thread is spawned per Start click, feeding a crossbeam channel back to the FLTK main loop via `app::channel`. State shared across threads (running flag, frame count, selected protocol) is wrapped in `Arc<Mutex<_>>`. Preserve this pattern when adding state — FLTK widgets must never be touched from the capture thread.
- No tests, no CI, no lints configured. Verify with `cargo build` (or `cargo clippy` if available).
