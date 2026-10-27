#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod entry;
#[cfg(feature = "gui")]
mod gui;
fn main() {
    entry::run();
}
