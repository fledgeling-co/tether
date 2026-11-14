//! The shared flows and copy from `tether-model`, as JSON commands.
//!
//! A flow handle is driven by performing each returned action: `send` writes `message` as a
//! control record, `receive` reads one and passes it to `flow.receive`, `wait` sleeps `ms` then
//! calls `flow.tick`, `show_code` puts the code on screen then calls `flow.shown`, `store_pending`
//! saves the unconfirmed record then calls `flow.stored`, `discard_pending` deletes it, and
//! `confirm` marks it confirmed. Every flow response also carries `state`.
use crate::{fixed, handle, text, Object, Registry};
use serde_json::{json, Value};
use tether_model::{code::CodeClient, discovery, invite, nearby::NearbyClient, view};

fn actions(list: Vec<tether_model::nearby::Action>) -> Value {
    Value::Array(list.iter().map(|action| action.json()).collect())
}

fn decision(request: &Value) -> Result<Option<bool>, &'static str> {
    match request.get("decision") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(answer)) => Ok(Some(*answer)),
        _ => Err("invalid_request"),
    }
}

fn now(request: &Value) -> Result<u64, &'static str> {
    request
        .get("now")
        .and_then(Value::as_u64)
        .ok_or("invalid_request")
}

fn flag(request: &Value, key: &str) -> bool {
    request.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn optional<'a>(request: &'a Value, key: &str) -> Option<&'a str> {
    request.get(key).and_then(Value::as_str)
}

fn state(object: &Object, now: u64) -> Value {
    match object {
        Object::Nearby(flow) => json!({
            "kind": "nearby", "phase": flow.phase().name(), "code": flow.code(),
            "hostApproved": flow.host_approved(), "declinedBySelf": flow.declined_by_self(),
            "error": flow.error(), "remainingMs": flow.remaining_ms(now),
            "canApprove": flow.can_approve(now),
        }),
        Object::Code(flow) => json!({
            "kind": "code",
            "phase": if flow.paired() { "connected" } else if flow.error().is_some() { "failed" } else { "checking" },
            "error": flow.error(),
        }),
        _ => Value::Null,
    }
}

pub(crate) fn flow(
    command: &str,
    request: &Value,
    registry: &mut Registry,
) -> Result<Value, &'static str> {
    let mut started = |object: Object, list| -> Result<Value, &'static str> {
        let view = state(&object, 0);
        let id = registry.insert(object)?;
        Ok(json!({"handle": id, "actions": actions(list), "state": view}))
    };
    match command {
        "nearby.begin" => {
            let (flow, list) = NearbyClient::begin(
                text(request, "app")?,
                fixed(request, "binding")?,
                fixed(request, "clientKey")?,
                fixed(request, "hostKey")?,
                text(request, "name")?,
                optional(request, "kind").unwrap_or("Device"),
                optional(request, "inviteToken"),
            )
            .map_err(|_| "crypto_refused")?;
            started(Object::Nearby(Box::new(flow)), list)
        }
        "code.begin" => {
            let (flow, list) = CodeClient::begin(
                text(request, "app")?,
                text(request, "code")?,
                fixed(request, "binding")?,
                fixed(request, "clientKey")?,
                fixed(request, "hostKey")?,
            )
            .map_err(|_| "invalid_code")?;
            started(Object::Code(Box::new(flow)), list)
        }
        _ => {
            let id = handle(request)?;
            let object = registry.objects.get_mut(&id).ok_or("invalid_handle")?;
            let at = match command {
                "flow.stored" | "flow.state" => {
                    request.get("now").and_then(Value::as_u64).unwrap_or(0)
                }
                _ => now(request)?,
            };
            let list = match (command, &mut *object) {
                ("flow.receive", object) => {
                    let message = request
                        .get("message")
                        .filter(|m| m.is_object())
                        .ok_or("invalid_request")?;
                    match object {
                        Object::Nearby(flow) => flow.receive(message, decision(request)?, at),
                        Object::Code(flow) => flow.receive(message),
                        _ => return Err("invalid_handle_type"),
                    }
                }
                ("flow.tick", Object::Nearby(flow)) => flow.tick(decision(request)?, at),
                ("flow.shown", Object::Nearby(flow)) => flow.shown(decision(request)?, at),
                ("flow.tick", Object::Code(_)) => Vec::new(),
                ("flow.stored", Object::Nearby(flow)) => flow.stored(decision(request)?),
                ("flow.stored", Object::Code(flow)) => flow.stored(),
                ("flow.state", Object::Nearby(_) | Object::Code(_)) => Vec::new(),
                ("flow.view", Object::Nearby(flow)) => {
                    return Ok(view::nearby(
                        flow.phase().name(),
                        optional(request, "peer").unwrap_or(""),
                        optional(request, "device").unwrap_or("device"),
                        flag(request, "incoming"),
                        flow.code(),
                        flow.remaining_ms(at),
                        flow.can_approve(at),
                        flow.host_approved(),
                        flow.declined_by_self(),
                        flow.error(),
                    ))
                }
                _ => return Err("invalid_handle_type"),
            };
            Ok(json!({"actions": actions(list), "state": state(object, at)}))
        }
    }
}

fn strings(request: &Value, key: &str) -> Vec<String> {
    request
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(32)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn port(request: &Value, key: &str) -> u16 {
    request
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(0)
}

/// Copy and record formats: no handles, no secrets kept.
pub(crate) fn stateless(command: &str, request: &Value) -> Result<Value, &'static str> {
    let ms = |key: &str| request.get(key).and_then(Value::as_u64);
    match command {
        "ui.nearby" => Ok(view::nearby(
            text(request, "phase")?,
            optional(request, "peer").unwrap_or(""),
            optional(request, "device").unwrap_or("device"),
            flag(request, "incoming"),
            optional(request, "code"),
            ms("remainingMs"),
            flag(request, "canApprove"),
            flag(request, "hostApproved"),
            flag(request, "declinedBySelf"),
            optional(request, "error"),
        )),
        "ui.pair_code" => Ok(view::pair_code(
            optional(request, "state").unwrap_or("entry"),
            optional(request, "peer").unwrap_or(""),
            optional(request, "text").unwrap_or(""),
            optional(request, "error"),
        )),
        "ui.host_request" => Ok(view::host_request(
            optional(request, "name").unwrap_or(""),
            text(request, "code")?,
            ms("remainingMs").unwrap_or(0),
            ms("shownMs").unwrap_or(0),
            flag(request, "deviceApproved"),
            flag(request, "invited"),
            &strings(request, "services"),
        )),
        "ui.connection_state" => Ok(view::connection_state(text(request, "state")?)),
        "ui.strings" => Ok(view::strings(
            optional(request, "device").unwrap_or("device"),
        )),
        "ui.error" => Ok(json!({"message": view::error_message(
            optional(request, "code").unwrap_or(""),
            optional(request, "peer").unwrap_or("the computer"),
        )})),
        "ui.label" => Ok(json!({"text": view::label(
            optional(request, "text").unwrap_or(""),
            optional(request, "fallback").unwrap_or("Device"),
        )})),
        "ui.code" => Ok(view::code(text(request, "digits")?)),
        "ui.expiry" => Ok(json!({"text": view::expiry(ms("remainingMs").unwrap_or(0))})),
        "discovery.services" => {
            Ok(json!({"host": discovery::HOST_SERVICE, "device": discovery::DEVICE_SERVICE}))
        }
        "discovery.txt" => Ok(json!({"txt": discovery::txt(
            text(request, "app")?,
            optional(request, "name").unwrap_or(""),
            optional(request, "kind").unwrap_or(""),
            port(request, "port"),
            optional(request, "hostKey"),
            &strings(request, "addresses"),
        )})),
        "discovery.peer" => Ok(json!({"peer": discovery::peer(
            text(request, "app")?,
            text(request, "id")?,
            optional(request, "serviceName").unwrap_or(""),
            request.get("txt").unwrap_or(&Value::Null),
            &strings(request, "resolved"),
            port(request, "port"),
        )})),
        "discovery.invite_token" => Ok(json!({"token": discovery::invite_token()})),
        "discovery.challenge" => Ok(json!({"line": discovery::challenge(
            text(request, "app")?,
            text(request, "token")?,
        )?
        .to_string()})),
        "discovery.read_challenge" => Ok(json!({"token": discovery::read_challenge(
            text(request, "app")?,
            text(request, "line")?,
        )})),
        "discovery.invite" => Ok(json!({"line": discovery::invite(
            text(request, "app")?,
            optional(request, "name").unwrap_or(""),
            port(request, "port"),
            text(request, "token")?,
        )?
        .to_string()})),
        "discovery.read_invite" => Ok(json!({"invite": discovery::read_invite(
            text(request, "app")?,
            text(request, "line")?,
            text(request, "remote")?,
            text(request, "token")?,
        )})),
        "discovery.route" => Ok(json!({"route": invite::route(
            request.get("route").ok_or("invalid_request")?,
            flag(request, "allowLoopback"),
        )?})),
        "discovery.read_invitation" => invite::read(
            text(request, "url")?,
            text(request, "app")?,
            ms("now").ok_or("invalid_request")?,
        ),
        "discovery.invitation" => Ok(json!({"url": invite::write(
            text(request, "app")?,
            request.get("route").ok_or("invalid_request")?,
            text(request, "code")?,
            ms("expiresAtMs").ok_or("invalid_request")?,
            ms("now").ok_or("invalid_request")?,
        )?})),
        _ => Err("invalid_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::collections::HashMap;

    fn call(registry: &mut Registry, value: Value) -> Value {
        crate::perform(&value, registry).expect("flow command")
    }

    #[test]
    fn a_nearby_flow_runs_over_json_and_its_view_follows_the_state() {
        let mut registry = Registry {
            next: 1,
            objects: HashMap::new(),
        };
        let key = |b: u8| STANDARD.encode([b; 32]);
        let begun = call(
            &mut registry,
            json!({"command":"nearby.begin","app":"app.test","binding":key(7),"clientKey":key(1),"hostKey":key(2),"name":"Field iPhone","kind":"iPhone"}),
        );
        assert_eq!(begun["actions"][0]["do"], "send");
        assert_eq!(begun["actions"][0]["message"]["type"], "pair.nearby");
        let commit = STANDARD
            .decode(begun["actions"][0]["message"]["commit"].as_str().unwrap())
            .unwrap();
        let (host, nonce) =
            tether_core::SasHost::start("app.test", [7; 32], [1; 32], [2; 32], &commit).unwrap();
        let handle = begun["handle"].clone();
        let revealed = call(
            &mut registry,
            json!({"command":"flow.receive","handle":handle,"now":0,"message":{"type":"pair.nearby.nonce","v":1,"nonce":STANDARD.encode(nonce)}}),
        );
        let reveal = STANDARD
            .decode(revealed["actions"][0]["message"]["nonce"].as_str().unwrap())
            .unwrap();
        let digits = host.finish(&reveal).unwrap().digits().to_owned();
        let held = call(
            &mut registry,
            json!({"command":"flow.receive","handle":handle,"now":10,"decision":null,"message":{"type":"pair.nearby.held","v":1}}),
        );
        assert_eq!(held["actions"], json!([{"do":"show_code","code":digits}]));
        let shown = call(
            &mut registry,
            json!({"command":"flow.shown","handle":handle,"now":10,"decision":null}),
        );
        assert_eq!(shown["actions"][0]["message"]["type"], "pair.nearby.poll");
        assert_eq!(shown["state"]["canApprove"], false);
        let view = call(
            &mut registry,
            json!({"command":"flow.view","handle":handle,"now":1_200,"peer":"Studio Mac","device":"iPhone"}),
        );
        assert_eq!(view["primary"]["enabled"], true);
        assert_eq!(view["title"], "Connect to Studio Mac?");
        assert!(crate::perform(
            &json!({"command":"flow.tick","handle":handle,"now":"soon"}),
            &mut registry
        )
        .is_err());
    }

    #[test]
    fn the_invite_exchange_answers_over_the_abi_and_refuses_an_untokened_line() {
        let token = stateless("discovery.invite_token", &json!({})).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        let challenge = stateless(
            "discovery.challenge",
            &json!({"app":"app.test","token":token}),
        )
        .unwrap()["line"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            stateless(
                "discovery.read_challenge",
                &json!({"app":"app.test","line":challenge})
            )
            .unwrap()["token"],
            token
        );
        let line = stateless(
            "discovery.invite",
            &json!({"app":"app.test","name":"Studio Mac","port":15912,"token":token}),
        )
        .unwrap()["line"]
            .as_str()
            .unwrap()
            .to_owned();
        let read = stateless(
            "discovery.read_invite",
            &json!({"app":"app.test","line":line,"remote":"192.168.1.5","token":token}),
        )
        .unwrap();
        assert_eq!(read["invite"]["port"], 15912);
        assert_eq!(read["invite"]["token"], token);
        // The line anybody on the network could compose carries no token, so no kit reads it.
        assert_eq!(
            stateless("discovery.read_invite", &json!({"app":"app.test","line":"{\"v\":1,\"app\":\"app.test\",\"port\":15912}","remote":"192.168.1.5","token":token})).unwrap()["invite"],
            Value::Null
        );
        assert_eq!(
            stateless(
                "discovery.invite",
                &json!({"app":"app.test","name":"x","port":1,"token":"short"})
            ),
            Err("invalid_token")
        );
        // And the token travels on pair.nearby, which is what makes a host's invited marking mean something.
        let mut registry = Registry {
            next: 1,
            objects: HashMap::new(),
        };
        let begun = call(
            &mut registry,
            json!({"command":"nearby.begin","app":"app.test","binding":STANDARD.encode([7u8;32]),
                   "clientKey":STANDARD.encode([1u8;32]),"hostKey":STANDARD.encode([2u8;32]),
                   "name":"Phone","kind":"iPhone","inviteToken":token}),
        );
        assert_eq!(begun["actions"][0]["message"]["tok"], token);
    }

    #[test]
    fn copy_and_invitations_answer_without_a_handle() {
        let view = stateless("ui.pair_code", &json!({"text":"K7QN-4FMB"})).unwrap();
        assert_eq!(view["primary"]["label"], "Pair");
        assert_eq!(view["primary"]["enabled"], true);
        let route =
            json!({"mode":"cloud","relayUrl":"wss://relay.example","hostId":"b".repeat(52)});
        let link = stateless(
            "discovery.invitation",
            &json!({"app":"app.test","route":route,"code":"K7QN4FMB","expiresAtMs":1_000_060_000u64,"now":1_000_000_000u64}),
        )
        .unwrap();
        let read = stateless(
            "discovery.read_invitation",
            &json!({"app":"app.test","url":link["url"],"now":1_000_000_000u64}),
        )
        .unwrap();
        assert_eq!(read["route"], route);
        assert_eq!(
            stateless("ui.error", &json!({"code":"busy","peer":"Studio Mac"})).unwrap()["message"],
            "Studio Mac is already showing another request. Try again in a moment."
        );
        assert_eq!(stateless("ui.bogus", &json!({})), Err("invalid_command"));
    }
}
