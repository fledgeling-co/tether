#![recursion_limit = "256"]
//! Shared, I/O-free Tether client logic. Every kit drives these state machines and renders these
//! view models, so the protocol rules and the words on screen are decided once.
pub mod code;
pub mod discovery;
pub mod invite;
pub mod nearby;
pub mod view;
