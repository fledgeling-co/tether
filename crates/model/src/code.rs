//! The client side of typed-code pairing as a state machine, driven the same way as
//! [`crate::nearby::NearbyClient`]: perform each returned action, then report back with
//! [`CodeClient::receive`] or [`CodeClient::stored`].
use crate::nearby::{Action, Outcome};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use tether_core::{Confirmation, Pairing, Role};

enum Step {
    AwaitReply(Box<Pairing>),
    AwaitReady,
    AwaitAck,
    AwaitDone,
    Done,
}

pub struct CodeClient {
    step: Step,
    error: Option<String>,
    paired: bool,
}

impl CodeClient {
    /// Starts after the encrypted channel is up. `binding` is its handshake hash; `code` is what
    /// the owner typed, in any case and with or without separators.
    pub fn begin(
        app_id: &str,
        code: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
    ) -> Result<(Self, Vec<Action>), tether_core::Error> {
        let (pairing, element) =
            Pairing::start(Role::Client, code, app_id, binding, client_key, host_key)?;
        let client = Self {
            step: Step::AwaitReply(Box::new(pairing)),
            error: None,
            paired: false,
        };
        let start = json!({"type":"pair.start","v":1,"element":STANDARD.encode(element)});
        Ok((client, vec![Action::Send(start), Action::Receive]))
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    pub fn paired(&self) -> bool {
        self.paired
    }

    fn fail(&mut self, code: &str) -> Vec<Action> {
        self.step = Step::Done;
        self.error = Some(code.to_owned());
        vec![Action::Failed(code.to_owned())]
    }

    fn confirm(pairing: Pairing, message: &Value) -> Option<Confirmation> {
        let element = STANDARD.decode(message["element"].as_str()?).ok()?;
        let proof = STANDARD.decode(message["proof"].as_str()?).ok()?;
        let confirmation = pairing.finish(&element).ok()?;
        confirmation.verify_peer(&proof).ok()?;
        Some(confirmation)
    }

    /// A control record arrived from the host.
    pub fn receive(&mut self, message: &Value) -> Vec<Action> {
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
            Step::AwaitReply(pairing) if kind == "pair.reply" => {
                // A wrong code shows up here as a proof that doesn't verify.
                let Some(confirmation) = Self::confirm(*pairing, message) else {
                    return self.fail("invalid_code");
                };
                self.step = Step::AwaitReady;
                let proof = STANDARD.encode(confirmation.outbound());
                vec![
                    Action::Send(json!({"type":"pair.confirm","v":1,"proof":proof})),
                    Action::Receive,
                ]
            }
            Step::AwaitReady if kind == "pair.ready" => {
                self.step = Step::AwaitAck;
                vec![Action::StorePending]
            }
            Step::AwaitDone if kind == "pair.done" => {
                self.paired = true;
                vec![Action::Confirm, Action::Outcome(Outcome::Paired)]
            }
            Step::AwaitDone => self.fail("pairing_pending"),
            _ => self.fail("invalid_protocol"),
        }
    }

    /// The pending record is saved. The host stores the device only after this ack.
    pub fn stored(&mut self) -> Vec<Action> {
        match self.step {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn host_reply(client_message: &Value, code: &str) -> (Confirmation, Value) {
        let element = STANDARD
            .decode(client_message["element"].as_str().unwrap())
            .unwrap();
        let (host, reply) =
            Pairing::start(Role::Host, code, "app.test", [7; 32], [1; 32], [2; 32]).unwrap();
        let confirmation = host.finish(&element).unwrap();
        let message = json!({"type":"pair.reply","v":1,"element":STANDARD.encode(reply),"proof":STANDARD.encode(confirmation.outbound())});
        (confirmation, message)
    }

    #[test]
    fn a_matching_code_runs_to_paired_and_stores_before_ack() {
        let (mut client, actions) =
            CodeClient::begin("app.test", "k7qn-4fmb", [7; 32], [1; 32], [2; 32]).unwrap();
        let Action::Send(start) = &actions[0] else {
            panic!("expected send")
        };
        let (host, reply) = host_reply(start, "K7QN4FMB");
        let actions = client.receive(&reply);
        let Action::Send(confirm) = &actions[0] else {
            panic!("expected confirm")
        };
        host.verify_peer(&STANDARD.decode(confirm["proof"].as_str().unwrap()).unwrap())
            .unwrap();
        assert_eq!(
            client.receive(&json!({"type":"pair.ready","v":1})),
            vec![Action::StorePending]
        );
        assert_eq!(
            client.stored()[0],
            Action::Send(json!({"type":"pair.ack","v":1}))
        );
        assert_eq!(
            client.receive(&json!({"type":"pair.done","v":1})),
            vec![Action::Confirm, Action::Outcome(Outcome::Paired)]
        );
        assert!(client.paired());
    }

    #[test]
    fn a_wrong_code_or_host_error_fails_without_storing() {
        let (mut client, actions) =
            CodeClient::begin("app.test", "K7QN4FMB", [7; 32], [1; 32], [2; 32]).unwrap();
        let Action::Send(start) = &actions[0] else {
            panic!("expected send")
        };
        let (_, reply) = host_reply(start, "K7QN4FMC");
        assert_eq!(
            client.receive(&reply),
            vec![Action::Failed("invalid_code".into())]
        );
        let (mut other, _) =
            CodeClient::begin("app.test", "K7QN4FMB", [7; 32], [1; 32], [2; 32]).unwrap();
        assert_eq!(
            other.receive(&json!({"type":"error","v":1,"code":"pairing_closed"})),
            vec![Action::Failed("pairing_closed".into())]
        );
        assert_eq!(other.stored(), vec![Action::Failed("invalid_state".into())]);
    }
}
