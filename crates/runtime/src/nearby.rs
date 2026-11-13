//! Nearby pairing requests held by a host until its owner approves or declines them.
//!
//! A request exists only after the code-comparison exchange has produced a code, and it holds
//! that code for the owner's own screen. Nothing here grants access: a request becomes a device
//! record only through the ordinary ready / ack / done sequence, after both the owner and the
//! requesting device have approved the same code.
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    time::{Duration, Instant},
};
use tether_core::SasCode;

/// How long both owners have to compare the code and approve it.
pub const LIFETIME: Duration = Duration::from_secs(60);
/// Requests held at once. A busy network cannot queue prompts behind the one being read.
pub const CONCURRENT: usize = 2;
/// Declines from one device key before that key is paused.
pub const DECLINES: u8 = 3;
pub const PAUSE: Duration = Duration::from_secs(600);
/// The fastest a client may poll, so a request cannot become a busy loop.
pub const POLL_FLOOR: Duration = Duration::from_millis(250);
/// Exchanges this host will start in one window, across every device key. Each one gives a
/// device in the middle one chance in a million, so the budget bounds its odds per window.
pub const ATTEMPTS: usize = 12;
pub const WINDOW: Duration = Duration::from_secs(600);
/// Exchanges abandoned after the host's nonce and before a valid reveal. An honest device never
/// does this; a device in the middle trying for a matching code does. Reaching this closes
/// nearby pairing until the owner opens it again.
pub const UNFINISHED: usize = 3;

pub struct Request {
    pub peer: [u8; 32],
    pub name: String,
    pub kind: String,
    pub code: SasCode,
    pub expires: Instant,
    pub client_approved: bool,
    pub decision: Option<bool>,
}

struct Declines {
    count: u8,
    first: Instant,
    until: Option<Instant>,
}

pub enum Admission {
    Admitted(u64),
    Paused,
    Busy,
    Closed,
}

/// Why nearby pairing was closed without the owner choosing to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    Unfinished,
}

/// Where a held request stands when the client next asks.
#[derive(Debug, PartialEq, Eq)]
pub enum Standing {
    Waiting { host_approved: bool },
    Ready,
    Declined,
    Expired,
    Gone,
}

pub struct State {
    allow: bool,
    closed: Option<Closed>,
    requests: BTreeMap<u64, Request>,
    declines: HashMap<[u8; 32], Declines>,
    issued: VecDeque<Instant>,
    unfinished: VecDeque<Instant>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            allow: true,
            closed: None,
            requests: BTreeMap::new(),
            declines: HashMap::new(),
            issued: VecDeque::new(),
            unfinished: VecDeque::new(),
        }
    }
}

impl State {
    fn sweep(&mut self, now: Instant) {
        // A declined request stays until the client hears about it or it expires.
        self.requests.retain(|_, request| request.expires > now);
        self.declines.retain(|_, entry| match entry.until {
            Some(until) => until > now,
            None => now.duration_since(entry.first) < PAUSE,
        });
        // Bounded: a flood of fresh keys cannot grow this without limit.
        while self.declines.len() > 256 {
            let Some(oldest) = self
                .declines
                .iter()
                .min_by_key(|(_, entry)| entry.first)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.declines.remove(&oldest);
        }
        while self
            .issued
            .front()
            .is_some_and(|at| now.duration_since(*at) >= WINDOW)
        {
            self.issued.pop_front();
        }
        while self
            .unfinished
            .front()
            .is_some_and(|at| now.duration_since(*at) >= WINDOW)
        {
            self.unfinished.pop_front();
        }
    }

    pub fn allows(&self) -> bool {
        self.allow
    }

    /// The owner opens or closes nearby pairing. Closing ends every held request.
    pub fn set_allow(&mut self, allow: bool) {
        self.allow = allow;
        if allow {
            self.closed = None;
            self.unfinished.clear();
        } else {
            for request in self.requests.values_mut() {
                request.decision = Some(false);
            }
        }
    }

    /// Spends one attempt before the host's nonce is sent. Every exchange counts, whether or not
    /// it reaches a request, so a device in the middle cannot try codes the owner never sees.
    pub fn issue(&mut self, now: Instant) -> bool {
        self.sweep(now);
        if !self.allow || self.issued.len() >= ATTEMPTS {
            return false;
        }
        self.issued.push_back(now);
        true
    }

    /// An exchange ended between the host's nonce and a valid reveal.
    pub fn unfinished(&mut self, now: Instant) {
        self.sweep(now);
        self.unfinished.push_back(now);
        if self.unfinished.len() >= UNFINISHED {
            self.set_allow(false);
            self.closed = Some(Closed::Unfinished);
        }
    }

    pub fn paused(&mut self, peer: &[u8; 32], now: Instant) -> bool {
        self.sweep(now);
        self.declines
            .get(peer)
            .and_then(|entry| entry.until)
            .is_some_and(|until| until > now)
    }

    /// Admits a request whose code both sides can now display.
    pub fn admit(
        &mut self,
        peer: [u8; 32],
        name: String,
        kind: String,
        code: SasCode,
        now: Instant,
    ) -> Admission {
        self.sweep(now);
        if !self.allow {
            return Admission::Closed;
        }
        if self.paused(&peer, now) {
            return Admission::Paused;
        }
        // One device holds at most one request; a repeat replaces nothing and waits its turn.
        let open = self
            .requests
            .values()
            .filter(|request| request.decision != Some(false));
        if open.clone().count() >= CONCURRENT || open.clone().any(|request| request.peer == peer) {
            return Admission::Busy;
        }
        // Random, so an owner reply from before a restart cannot match a new request.
        let mut id = rand::random::<u64>() | 1;
        while self.requests.contains_key(&id) {
            id = rand::random::<u64>() | 1;
        }
        self.requests.insert(
            id,
            Request {
                peer,
                name,
                kind,
                code,
                expires: now + LIFETIME,
                client_approved: false,
                decision: None,
            },
        );
        Admission::Admitted(id)
    }

    /// The owner's decision. Returns false for an unknown or already-ended request.
    pub fn decide(&mut self, id: u64, approve: bool, now: Instant) -> bool {
        self.sweep(now);
        let Some(request) = self.requests.get_mut(&id) else {
            return false;
        };
        if request.decision.is_some() {
            return false;
        }
        request.decision = Some(approve);
        if !approve {
            let peer = request.peer;
            self.record_decline(peer, now);
        }
        true
    }

    fn record_decline(&mut self, peer: [u8; 32], now: Instant) {
        let entry = self.declines.entry(peer).or_insert(Declines {
            count: 0,
            first: now,
            until: None,
        });
        entry.count = entry.count.saturating_add(1);
        if entry.count >= DECLINES {
            entry.until = Some(now + PAUSE);
        }
    }

    /// The client's latest decision, then where the request stands.
    pub fn poll(&mut self, id: u64, client: Option<bool>, now: Instant) -> Standing {
        let Some(request) = self.requests.get_mut(&id) else {
            return Standing::Gone;
        };
        if request.expires <= now {
            self.requests.remove(&id);
            return Standing::Expired;
        }
        match client {
            Some(false) => {
                self.requests.remove(&id);
                return Standing::Declined;
            }
            Some(true) => request.client_approved = true,
            None => {}
        }
        match request.decision {
            Some(false) => {
                self.requests.remove(&id);
                Standing::Declined
            }
            Some(true) if request.client_approved => {
                self.requests.remove(&id);
                Standing::Ready
            }
            decision => Standing::Waiting {
                host_approved: decision == Some(true),
            },
        }
    }

    pub fn forget(&mut self, id: u64) {
        self.requests.remove(&id);
    }

    /// The owner's view. The code is shown only on the owner's own private channel.
    pub fn listing(&mut self, now: Instant) -> serde_json::Value {
        self.sweep(now);
        serde_json::json!({
            "allow": self.allow,
            "closed": self.closed.map(|_| "unfinished"),
            "attempts_remaining": ATTEMPTS.saturating_sub(self.issued.len()),
            "requests": self.requests.iter().filter(|(_, request)| request.decision != Some(false)).map(|(id, request)| serde_json::json!({
                "id": id,
                "name": request.name,
                "kind": request.kind,
                "code": request.code.digits(),
                "expires_in_seconds": request.expires.saturating_duration_since(now).as_secs(),
                "client_approved": request.client_approved,
                "decision": request.decision,
            })).collect::<Vec<_>>()
        })
    }
}

/// A device name is a label the requester chose. It is displayed beside the code, never trusted.
pub fn label(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .take(48)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        fallback.to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tether_core::{SasClient, SasHost};

    fn code() -> SasCode {
        let (client, commitment) = SasClient::start("test.app", [7; 32], [1; 32], [2; 32]).unwrap();
        let (host, nonce) =
            SasHost::start("test.app", [7; 32], [1; 32], [2; 32], &commitment).unwrap();
        let (reveal, _) = client.finish(&nonce).unwrap();
        host.finish(&reveal).unwrap()
    }
    fn admit(state: &mut State, peer: u8, now: Instant) -> u64 {
        match state.admit([peer; 32], "Phone".into(), "iPhone".into(), code(), now) {
            Admission::Admitted(id) => id,
            _ => panic!("refused"),
        }
    }

    #[test]
    fn ready_needs_both_approvals_in_either_order() {
        let now = Instant::now();
        let mut state = State::default();
        let first = admit(&mut state, 1, now);
        assert_eq!(
            state.poll(first, Some(true), now),
            Standing::Waiting {
                host_approved: false
            }
        );
        assert!(state.decide(first, true, now));
        assert_eq!(state.poll(first, None, now), Standing::Ready);
        let second = admit(&mut state, 2, now);
        assert!(state.decide(second, true, now));
        assert_eq!(
            state.poll(second, None, now),
            Standing::Waiting {
                host_approved: true
            }
        );
        assert_eq!(state.poll(second, Some(true), now), Standing::Ready);
        assert_eq!(state.poll(second, None, now), Standing::Gone);
    }

    #[test]
    fn either_decline_ends_it_and_a_late_approval_cannot_revive_it() {
        let now = Instant::now();
        let mut state = State::default();
        let id = admit(&mut state, 1, now);
        assert!(state.decide(id, false, now));
        assert!(!state.decide(id, true, now));
        assert_eq!(state.poll(id, Some(true), now), Standing::Declined);
        assert_eq!(state.poll(id, Some(true), now), Standing::Gone);
        let other = admit(&mut state, 2, now);
        assert!(state.decide(other, true, now));
        assert_eq!(state.poll(other, Some(false), now), Standing::Declined);
        assert!(!state.decide(other, true, now));
    }

    #[test]
    fn requests_expire_and_cannot_be_approved_afterwards() {
        let now = Instant::now();
        let mut state = State::default();
        let id = admit(&mut state, 1, now);
        let later = now + LIFETIME + Duration::from_millis(1);
        assert!(!state.decide(id, true, later));
        assert_eq!(state.poll(id, Some(true), later), Standing::Gone);
    }

    #[test]
    fn repeated_declines_pause_a_device_and_concurrency_is_bounded() {
        let now = Instant::now();
        let mut state = State::default();
        for _ in 0..DECLINES {
            let id = admit(&mut state, 9, now);
            assert!(state.decide(id, false, now));
        }
        assert!(matches!(
            state.admit([9; 32], "x".into(), "x".into(), code(), now),
            Admission::Paused
        ));
        assert!(matches!(
            state.admit(
                [9; 32],
                "x".into(),
                "x".into(),
                code(),
                now + PAUSE + Duration::from_secs(1)
            ),
            Admission::Admitted(_)
        ));
        let mut fresh = State::default();
        admit(&mut fresh, 1, now);
        assert!(matches!(
            fresh.admit([1; 32], "x".into(), "x".into(), code(), now),
            Admission::Busy
        ));
        admit(&mut fresh, 2, now);
        assert!(matches!(
            fresh.admit([3; 32], "x".into(), "x".into(), code(), now),
            Admission::Busy
        ));
    }

    #[test]
    fn unfinished_exchanges_close_nearby_pairing_until_the_owner_reopens_it() {
        let now = Instant::now();
        let mut state = State::default();
        for _ in 0..UNFINISHED {
            assert!(state.issue(now));
            state.unfinished(now);
        }
        assert!(!state.allows());
        assert!(!state.issue(now));
        assert!(matches!(
            state.admit([1; 32], "x".into(), "x".into(), code(), now),
            Admission::Closed
        ));
        assert_eq!(state.listing(now)["closed"], "unfinished");
        state.set_allow(true);
        assert!(state.issue(now));
    }

    #[test]
    fn the_attempt_budget_is_host_wide_and_renews_with_the_window() {
        let now = Instant::now();
        let mut state = State::default();
        for _ in 0..ATTEMPTS {
            assert!(state.issue(now));
        }
        assert!(!state.issue(now));
        assert!(state.issue(now + WINDOW));
    }

    #[test]
    fn closing_ends_held_requests_and_decline_records_expire() {
        let now = Instant::now();
        let mut state = State::default();
        let id = admit(&mut state, 1, now);
        state.set_allow(false);
        assert_eq!(state.poll(id, Some(true), now), Standing::Declined);
        state.set_allow(true);
        let other = admit(&mut state, 2, now);
        assert!(state.decide(other, false, now));
        assert_eq!(state.declines.len(), 1);
        state.sweep(now + PAUSE);
        assert!(state.declines.is_empty());
    }

    #[test]
    fn labels_drop_controls_and_direction_overrides_and_are_bounded() {
        assert_eq!(label("Field\u{202e}enohPi\n", "Device"), "FieldenohPi");
        assert_eq!(label("   ", "Device"), "Device");
        assert_eq!(label(&"x".repeat(200), "Device").chars().count(), 48);
    }
}
