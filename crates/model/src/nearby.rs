//! The client side of nearby pairing as a state machine. The caller owns the encrypted session,
//! persistent storage and the clock; this decides what to send, when, and what each reply means.
//!
//! Drive it with [`NearbyClient::begin`], then repeatedly perform the returned actions:
//! `send` writes a control record, `receive` reads one and passes it to [`NearbyClient::receive`],
//! `wait` sleeps then calls [`NearbyClient::tick`], `show_code` puts the code on screen then calls
//! [`NearbyClient::shown`], `store_pending` saves the unconfirmed record then calls
//! [`NearbyClient::stored`], `discard_pending` deletes it again, and `confirm` marks it confirmed.
//! `host_approved` and `outcome` are for the UI. Every call takes the owner's current decision
//! (`None` while undecided) and the time in milliseconds.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use tether_core::{SasClient, SAS_NONCE};

/// How long both owners have to approve, as the host enforces it.
pub const LIFETIME_MS: u64 = 60_000;
/// A code must be on screen this long before an approval counts.
pub const READ_MS: u64 = 1_000;
/// Pause between polls for the host's decision.
pub const POLL_MS: u64 = 600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(Value),
    Receive,
    Wait(u64),
    ShowCode(String),
    HostApproved,
    StorePending,
    DiscardPending,
    Confirm,
    Outcome(Outcome),
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Paired,
    Declined,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Checking,
    Code,
    Waiting,
    Storing,
    Connected,
    Declined,
    Expired,
    Failed,
}

enum Step {
    AwaitNonce(SasClient),
    AwaitHeld(String),
    AwaitShown,
    Polling,
    AwaitReady,
    AwaitAck,
    AwaitDone,
    Done,
}

pub struct NearbyClient {
    step: Step,
    phase: Phase,
    code: Option<String>,
    shown_at: Option<u64>,
    sent: Option<bool>,
    undecided: bool,
    host_approved: bool,
    declined_by_self: bool,
    error: Option<String>,
}

impl NearbyClient {
    /// Starts after the encrypted channel is up. `binding` is its handshake hash.
    pub fn begin(
        app_id: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
        device_name: &str,
        device_kind: &str,
    ) -> Result<(Self, Vec<Action>), tether_core::Error> {
        let (sas, commitment) = SasClient::start(app_id, binding, client_key, host_key)?;
        let message = json!({
            "type": "pair.nearby", "v": 1, "commit": STANDARD.encode(commitment),
            "name": crate::view::label(device_name, "Device"), "kind": crate::view::label(device_kind, "Device"),
        });
        let client = Self {
            step: Step::AwaitNonce(sas),
            phase: Phase::Checking,
            code: None,
            shown_at: None,
            sent: None,
            undecided: false,
            host_approved: false,
            declined_by_self: false,
            error: None,
        };
        Ok((client, vec![Action::Send(message), Action::Receive]))
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
    pub fn host_approved(&self) -> bool {
        self.host_approved
    }
    pub fn declined_by_self(&self) -> bool {
        self.declined_by_self
    }
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    /// Milliseconds until the request expires, from the moment the code appeared.
    pub fn remaining_ms(&self, now: u64) -> Option<u64> {
        self.shown_at
            .map(|shown| (shown + LIFETIME_MS).saturating_sub(now))
    }
    /// Whether an approval right now would count.
    pub fn can_approve(&self, now: u64) -> bool {
        self.phase == Phase::Code && self.shown_at.is_some_and(|shown| now >= shown + READ_MS)
    }

    fn fail(&mut self, code: &str) -> Vec<Action> {
        self.step = Step::Done;
        self.phase = Phase::Failed;
        self.error = Some(code.to_owned());
        vec![Action::Failed(code.to_owned())]
    }

    fn finish(&mut self, outcome: Outcome) -> Vec<Action> {
        self.step = Step::Done;
        self.phase = match outcome {
            Outcome::Paired => Phase::Connected,
            Outcome::Declined => Phase::Declined,
            Outcome::Expired => Phase::Expired,
        };
        vec![Action::Outcome(outcome)]
    }

    /// Applies the owner's current decision. An approval counts only if the decision has read
    /// undecided at least once since the code appeared and the code has been up for a second;
    /// a decline always counts and cannot be undone.
    fn effective(&mut self, decision: Option<bool>, now: u64) -> Option<bool> {
        if decision.is_none() {
            self.undecided = true;
        }
        match decision {
            Some(false) => Some(false),
            Some(true)
                if self.undecided && self.shown_at.is_some_and(|shown| now >= shown + READ_MS) =>
            {
                Some(true)
            }
            _ => None,
        }
    }

    fn poll(&mut self, decision: Option<bool>, now: u64) -> Vec<Action> {
        if self.remaining_ms(now) == Some(0) {
            return self.finish(Outcome::Expired);
        }
        let local = self.effective(decision, now);
        let answer = match (self.sent, local) {
            (None, Some(answer)) => {
                self.sent = Some(answer);
                Value::Bool(answer)
            }
            (Some(true), Some(false)) => {
                self.sent = Some(false);
                Value::Bool(false)
            }
            _ => Value::Null,
        };
        if self.sent == Some(true) && self.phase == Phase::Code {
            self.phase = Phase::Waiting;
        }
        if self.sent == Some(false) {
            self.declined_by_self = true;
        }
        self.step = Step::AwaitReady;
        vec![
            Action::Send(json!({"type":"pair.nearby.poll","v":1,"approve":answer})),
            Action::Receive,
        ]
    }

    /// Time passed. Call after a `wait`.
    pub fn tick(&mut self, decision: Option<bool>, now: u64) -> Vec<Action> {
        match self.step {
            Step::Polling => self.poll(decision, now),
            _ => Vec::new(),
        }
    }

    /// A control record arrived from the host.
    pub fn receive(&mut self, message: &Value, decision: Option<bool>, _now: u64) -> Vec<Action> {
        if message["v"] != 1 {
            return self.fail("invalid_protocol");
        }
        let kind = message["type"].as_str().unwrap_or("");
        if kind == "error" {
            let code = message["code"]
                .as_str()
                .unwrap_or("invalid_protocol")
                .to_owned();
            return self.fail(&code);
        }
        match std::mem::replace(&mut self.step, Step::Done) {
            Step::AwaitNonce(sas) => {
                if kind != "pair.nearby.nonce" {
                    return self.fail("invalid_protocol");
                }
                let Some(nonce) = message["nonce"]
                    .as_str()
                    .and_then(|text| STANDARD.decode(text).ok())
                else {
                    return self.fail("invalid_protocol");
                };
                if nonce.len() != SAS_NONCE {
                    return self.fail("invalid_protocol");
                }
                match sas.finish(&nonce) {
                    Ok((reveal, code)) => {
                        self.step = Step::AwaitHeld(code.digits().to_owned());
                        vec![
                            Action::Send(
                                json!({"type":"pair.nearby.reveal","v":1,"nonce":STANDARD.encode(reveal)}),
                            ),
                            Action::Receive,
                        ]
                    }
                    Err(_) => self.fail("invalid_protocol"),
                }
            }
            Step::AwaitHeld(code) => {
                if kind != "pair.nearby.held" {
                    return self.fail("invalid_protocol");
                }
                // The read timer starts only when the caller reports the code is on screen.
                self.code = Some(code.clone());
                self.phase = Phase::Code;
                self.step = Step::AwaitShown;
                vec![Action::ShowCode(code)]
            }
            Step::AwaitReady => match kind {
                "pair.ready" => {
                    // A decline that raced with ready still wins: without ack the host stores nothing.
                    if self.sent != Some(true) || decision == Some(false) {
                        self.declined_by_self = decision == Some(false);
                        return self.finish(Outcome::Declined);
                    }
                    self.phase = Phase::Storing;
                    self.step = Step::AwaitAck;
                    vec![Action::StorePending]
                }
                "pair.nearby.status" => match message["state"].as_str() {
                    Some("waiting") => {
                        if self.sent == Some(false) {
                            return self.finish(Outcome::Declined);
                        }
                        let mut actions = Vec::new();
                        if message["host_approved"] == true && !self.host_approved {
                            self.host_approved = true;
                            actions.push(Action::HostApproved);
                        }
                        self.step = Step::Polling;
                        actions.push(Action::Wait(POLL_MS));
                        actions
                    }
                    Some("declined") => self.finish(Outcome::Declined),
                    Some("expired") => self.finish(Outcome::Expired),
                    _ => self.fail("invalid_protocol"),
                },
                _ => self.fail("invalid_protocol"),
            },
            Step::AwaitDone => {
                if kind != "pair.done" {
                    return self.fail("pairing_pending");
                }
                self.step = Step::Done;
                self.phase = Phase::Connected;
                vec![Action::Confirm, Action::Outcome(Outcome::Paired)]
            }
            _ => self.fail("invalid_protocol"),
        }
    }

    /// The code is on screen. Call after the UI has committed it, not before: the second an
    /// approval has to wait, and the undecided read it needs, both start here.
    pub fn shown(&mut self, decision: Option<bool>, now: u64) -> Vec<Action> {
        match self.step {
            Step::AwaitShown => {
                self.shown_at = Some(now);
                // Nothing decided before the code appeared counts: the decision has to read
                // undecided at some point from here on.
                self.undecided = false;
                self.step = Step::Polling;
                self.poll(decision, now)
            }
            _ => self.fail("invalid_state"),
        }
    }

    /// The pending record is saved. The host stores the device only after this ack, so a decline
    /// up to this point still wins: the record is discarded and no ack is sent.
    pub fn stored(&mut self, decision: Option<bool>) -> Vec<Action> {
        match self.step {
            Step::AwaitAck if decision == Some(false) => {
                self.declined_by_self = true;
                let mut actions = vec![Action::DiscardPending];
                actions.extend(self.finish(Outcome::Declined));
                actions
            }
            Step::AwaitAck => {
                self.step = Step::AwaitDone;
                vec![
                    Action::Send(json!({"type":"pair.ack","v":1})),
                    Action::Receive,
                ]
            }
            _ => self.fail("invalid_state"),
        }
    }
}

impl Action {
    /// The action as JSON, for the FFI and the browser.
    pub fn json(&self) -> Value {
        match self {
            Action::Send(message) => json!({"do":"send","message":message}),
            Action::Receive => json!({"do":"receive"}),
            Action::Wait(ms) => json!({"do":"wait","ms":ms}),
            Action::ShowCode(code) => json!({"do":"show_code","code":code}),
            Action::HostApproved => json!({"do":"host_approved"}),
            Action::StorePending => json!({"do":"store_pending"}),
            Action::DiscardPending => json!({"do":"discard_pending"}),
            Action::Confirm => json!({"do":"confirm"}),
            Action::Outcome(outcome) => {
                json!({"do":"outcome","outcome":match outcome { Outcome::Paired => "paired", Outcome::Declined => "declined", Outcome::Expired => "expired" }})
            }
            Action::Failed(code) => json!({"do":"failed","code":code}),
        }
    }
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Checking => "checking",
            Phase::Code => "code",
            Phase::Waiting => "waiting",
            Phase::Storing => "storing",
            Phase::Connected => "connected",
            Phase::Declined => "declined",
            Phase::Expired => "expired",
            Phase::Failed => "failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tether_core::SasHost;

    const APP: &str = "test.app";
    fn host_reply(client_commit: &Value) -> (SasHost, Value) {
        let commitment = STANDARD
            .decode(client_commit["commit"].as_str().unwrap())
            .unwrap();
        let (host, nonce) = SasHost::start(APP, [7; 32], [1; 32], [2; 32], &commitment).unwrap();
        (
            host,
            json!({"type":"pair.nearby.nonce","v":1,"nonce":STANDARD.encode(nonce)}),
        )
    }
    fn sent(actions: &[Action]) -> Vec<Value> {
        actions
            .iter()
            .filter_map(|a| {
                if let Action::Send(m) = a {
                    Some(m.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    fn to_code(c: &mut NearbyClient, start: &[Action]) -> (String, Vec<Action>) {
        to_code_deciding(c, start, None)
    }
    fn to_code_deciding(
        c: &mut NearbyClient,
        start: &[Action],
        decision: Option<bool>,
    ) -> (String, Vec<Action>) {
        let (host, nonce) = host_reply(&sent(start)[0]);
        let reveal = c.receive(&nonce, None, 0);
        let revealed = STANDARD
            .decode(sent(&reveal)[0]["nonce"].as_str().unwrap())
            .unwrap();
        let host_code = host.finish(&revealed).unwrap();
        let held = c.receive(
            &json!({"type":"pair.nearby.held","v":1,"expires_in_seconds":60}),
            decision,
            1_000,
        );
        assert_eq!(held, vec![Action::ShowCode(host_code.digits().to_owned())]);
        (host_code.digits().to_owned(), c.shown(decision, 1_000))
    }
    fn waiting(host_approved: bool) -> Value {
        json!({"type":"pair.nearby.status","v":1,"state":"waiting","host_approved":host_approved})
    }

    #[test]
    fn both_approve_then_store_ack_and_confirm() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let (_, held) = to_code(&mut c, &start);
        assert_eq!(
            sent(&held)[0]["approve"],
            Value::Null,
            "the first poll after the code is undecided"
        );
        assert_eq!(
            c.receive(&waiting(true), None, 1_100),
            vec![Action::HostApproved, Action::Wait(POLL_MS)]
        );
        let poll = c.tick(Some(true), 2_200);
        assert_eq!(sent(&poll)[0]["approve"], true);
        assert_eq!(c.phase(), Phase::Waiting);
        assert_eq!(
            c.receive(&json!({"type":"pair.ready","v":1}), Some(true), 2_300),
            vec![Action::StorePending]
        );
        assert_eq!(sent(&c.stored(Some(true)))[0]["type"], "pair.ack");
        assert_eq!(
            c.receive(&json!({"type":"pair.done","v":1}), Some(true), 2_400),
            vec![Action::Confirm, Action::Outcome(Outcome::Paired)]
        );
    }

    #[test]
    fn an_approval_set_before_the_code_or_within_a_second_does_not_count() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let (_, held) = to_code_deciding(&mut c, &start, Some(true));
        assert_eq!(sent(&held)[0]["approve"], Value::Null);
        let _ = c.receive(&waiting(false), Some(true), 1_200);
        // Always "approve", never undecided: it never counts.
        assert_eq!(sent(&c.tick(Some(true), 3_000))[0]["approve"], Value::Null);
        let (mut quick, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut quick, &start);
        let _ = quick.receive(&waiting(false), None, 1_100);
        assert_eq!(
            sent(&quick.tick(Some(true), 1_500))[0]["approve"],
            Value::Null,
            "within the first second"
        );
        let _ = quick.receive(&waiting(false), Some(true), 1_600);
        assert_eq!(sent(&quick.tick(Some(true), 2_100))[0]["approve"], true);
    }

    #[test]
    fn the_second_starts_when_the_code_is_on_screen_not_when_it_arrives() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let (host, nonce) = host_reply(&sent(&start)[0]);
        let reveal = c.receive(&nonce, None, 0);
        let _ = host.finish(
            &STANDARD
                .decode(sent(&reveal)[0]["nonce"].as_str().unwrap())
                .unwrap(),
        );
        let held = c.receive(&json!({"type":"pair.nearby.held","v":1}), None, 1_000);
        assert!(
            sent(&held).is_empty(),
            "nothing is polled before the code is shown"
        );
        assert!(!c.can_approve(5_000));
        // Rendering took four seconds and an approval was already set: it doesn't count.
        assert_eq!(sent(&c.shown(Some(true), 5_000))[0]["approve"], Value::Null);
        assert!(!c.can_approve(5_500));
        assert!(c.can_approve(6_000));
        assert_eq!(c.remaining_ms(5_000), Some(LIFETIME_MS));
        assert_eq!(
            c.shown(None, 6_000),
            vec![Action::Failed("invalid_state".into())]
        );
    }

    #[test]
    fn a_decline_before_the_ack_discards_the_pending_record() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut c, &start);
        let _ = c.receive(&waiting(false), None, 1_200);
        let _ = c.tick(Some(true), 2_500);
        let _ = c.receive(&json!({"type":"pair.ready","v":1}), Some(true), 2_600);
        assert_eq!(
            c.stored(Some(false)),
            vec![Action::DiscardPending, Action::Outcome(Outcome::Declined)]
        );
        assert!(c.declined_by_self());
    }

    #[test]
    fn a_decline_is_final_and_beats_a_racing_ready() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut c, &start);
        let _ = c.receive(&waiting(false), None, 1_200);
        let _ = c.tick(Some(true), 2_500);
        assert_eq!(
            c.receive(&json!({"type":"pair.ready","v":1}), Some(false), 2_600),
            vec![Action::Outcome(Outcome::Declined)]
        );
        assert!(c.declined_by_self());
        let (mut d, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut d, &start);
        let _ = d.receive(&waiting(false), None, 1_200);
        assert_eq!(sent(&d.tick(Some(false), 1_300))[0]["approve"], false);
        assert_eq!(
            d.receive(&waiting(false), Some(true), 1_400),
            vec![Action::Outcome(Outcome::Declined)]
        );
    }

    #[test]
    fn host_decline_expiry_and_refusals_end_the_flow() {
        let (mut c, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut c, &start);
        assert_eq!(
            c.receive(
                &json!({"type":"pair.nearby.status","v":1,"state":"declined"}),
                None,
                2_000
            ),
            vec![Action::Outcome(Outcome::Declined)]
        );
        assert!(!c.declined_by_self());
        let (mut e, start) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        let _ = to_code(&mut e, &start);
        let _ = e.receive(&waiting(false), None, 1_200);
        assert_eq!(
            e.tick(None, 1_000 + LIFETIME_MS),
            vec![Action::Outcome(Outcome::Expired)],
            "the device's own clock"
        );
        let (mut f, _) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        assert_eq!(
            f.receive(&json!({"type":"error","v":1,"code":"paused"}), None, 0),
            vec![Action::Failed("paused".into())]
        );
        let (mut g, _) =
            NearbyClient::begin(APP, [7; 32], [1; 32], [2; 32], "Phone", "iPhone").unwrap();
        assert_eq!(
            g.receive(&json!({"type":"pair.ready","v":1}), Some(true), 0),
            vec![Action::Failed("invalid_protocol".into())],
            "ready before any code"
        );
    }
}
