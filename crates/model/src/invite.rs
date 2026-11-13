//! Routes and pairing invitations, checked the same way on every platform.
//!
//! An invitation is `tether://pair?data=<base64url JSON>`, a short-lived bearer secret holding the
//! route and the pairing code. Its JSON is the shape the first kit wrote: `expiresAt` is seconds
//! since 1 January 2001 and the route is `{"privateNetwork":{host,port}}` or
//! `{"cloud":{relayURL,hostID}}`. Everywhere else a route is `{"mode":"private",host,port}` or
//! `{"mode":"cloud",relayUrl,hostId}`.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

/// Seconds between the Unix epoch and the invitation epoch (2001-01-01T00:00:00Z).
const EPOCH_2001: f64 = 978_307_200.0;
/// An invitation lives at most five minutes (plus a second of clock slack).
const MAX_LIFETIME_MS: f64 = 301_000.0;
const CODE_ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn host_id(text: &str) -> bool {
    text.len() == 52
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// Checks a relay URL: `wss://` with a host and nothing that could carry credentials or state.
/// `ws://` is allowed only to loopback, and only when testing.
fn relay(url: &str, allow_loopback: bool) -> bool {
    if url.len() > 2048 || url.contains(['?', '#', '@']) || url.chars().any(char::is_whitespace) {
        return false;
    }
    let (rest, secure) = if let Some(rest) = url.strip_prefix("wss://") {
        (rest, true)
    } else if let Some(rest) = url.strip_prefix("ws://") {
        (rest, false)
    } else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    // An IPv6 literal must close its bracket; anything after the host is an optional port.
    let (host, after) = match authority.strip_prefix('[') {
        Some(inner) => match inner.find(']') {
            Some(end) => (&authority[..end + 2], &inner[end + 1..]),
            None => return false,
        },
        None => match authority.find(':') {
            Some(colon) => (&authority[..colon], &authority[colon..]),
            None => (authority, ""),
        },
    };
    let port_ok = after.is_empty()
        || after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .is_some_and(|p| p > 0);
    if host.is_empty()
        || host == "[]"
        || !port_ok
        || (!host.starts_with('[') && host.contains(['[', ']']))
    {
        return false;
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(|h| h.parse::<std::net::Ipv6Addr>().is_ok());
    if literal == Some(false) {
        return false;
    }
    secure || (allow_loopback && matches!(host, "127.0.0.1" | "[::1]"))
}

/// A route in its normal form, or `invalid_route`.
pub fn route(value: &Value, allow_loopback: bool) -> Result<Value, &'static str> {
    match value["mode"].as_str() {
        Some("private") => {
            let host = value["host"].as_str().unwrap_or("").trim();
            let port = value["port"].as_u64().filter(|p| (1..=65535).contains(p));
            let usable = !host.is_empty()
                && host.len() <= 320
                && !matches!(host, "0.0.0.0" | "::" | "[::]")
                && !host
                    .chars()
                    .any(|c| c.is_whitespace() || "/?#@".contains(c));
            match (usable, port) {
                (true, Some(port)) => Ok(json!({"mode":"private","host":host,"port":port})),
                _ => Err("invalid_route"),
            }
        }
        Some("cloud") => {
            let url = value["relayUrl"].as_str().unwrap_or("").trim();
            let id = value["hostId"].as_str().unwrap_or("").trim();
            if relay(url, allow_loopback) && host_id(id) {
                Ok(json!({"mode":"cloud","relayUrl":url,"hostId":id}))
            } else {
                Err("invalid_route")
            }
        }
        _ => Err("invalid_route"),
    }
}

/// Reads an invitation link for `app_id` at `now_ms` (Unix milliseconds). Returns
/// `{route, code, expiresAtMs}`; any fault is `invalid_route`, and a stale, foreign or malformed
/// payload is `invalid_invitation`.
pub fn read(url: &str, app_id: &str, now_ms: u64) -> Result<Value, &'static str> {
    let raw = url
        .trim()
        .strip_prefix("tether://pair?data=")
        .filter(|raw| {
            url.trim().len() <= 4096
                && !raw.is_empty()
                && raw.len() <= 3500
                && raw
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or("invalid_route")?;
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| "invalid_route")?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_route")?;
    let code = value["code"].as_str().unwrap_or("");
    let expiry = value["expiresAt"]
        .as_f64()
        .map(|seconds| (seconds + EPOCH_2001) * 1000.0)
        .filter(|ms| ms.is_finite());
    let now = now_ms as f64;
    let fresh = expiry.is_some_and(|ms| ms > now && ms - now <= MAX_LIFETIME_MS);
    if value["version"] != 1
        || value["appID"].as_str() != Some(app_id)
        || code.len() != 8
        || !code.chars().all(|c| CODE_ALPHABET.contains(c))
        || !fresh
    {
        return Err("invalid_invitation");
    }
    let wire = &value["route"];
    let normal = if wire["privateNetwork"].is_object() {
        json!({"mode":"private","host":wire["privateNetwork"]["host"],"port":wire["privateNetwork"]["port"]})
    } else if wire["cloud"].is_object() {
        json!({"mode":"cloud","relayUrl":wire["cloud"]["relayURL"],"hostId":wire["cloud"]["hostID"]})
    } else {
        return Err("invalid_route");
    };
    Ok(
        json!({"route": route(&normal, false)?, "code": code, "expiresAtMs": expiry.unwrap_or(0.0) as u64}),
    )
}

/// Writes an invitation link. `expires_ms` must be in the next five minutes.
pub fn write(
    app_id: &str,
    route_value: &Value,
    code: &str,
    expires_ms: u64,
    now_ms: u64,
) -> Result<String, &'static str> {
    let normal = route(route_value, false)?;
    let wire = match normal["mode"].as_str() {
        Some("private") => {
            json!({"privateNetwork":{"host":normal["host"],"port":normal["port"]}})
        }
        _ => json!({"cloud":{"relayURL":normal["relayUrl"],"hostID":normal["hostId"]}}),
    };
    let payload = json!({
        "version": 1, "appID": app_id, "route": wire, "code": code,
        "expiresAt": expires_ms as f64 / 1000.0 - EPOCH_2001,
    });
    let link = format!(
        "tether://pair?data={}",
        URL_SAFE_NO_PAD.encode(payload.to_string())
    );
    // Writing then reading proves the link is one every kit accepts.
    read(&link, app_id, now_ms)?;
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_800_000_000_000;

    #[test]
    fn invitations_round_trip_and_match_the_swift_encoding() {
        let cloud =
            json!({"mode":"cloud","relayUrl":"wss://relay.example/v1","hostId":"a".repeat(52)});
        let link = write("app.test", &cloud, "K7QN4FMB", NOW + 60_000, NOW).unwrap();
        let read_back = read(&link, "app.test", NOW).unwrap();
        assert_eq!(read_back["route"], cloud);
        assert_eq!(read_back["code"], "K7QN4FMB");
        // The payload the Android tests build by hand reads the same way.
        let android = json!({"version":1,"appID":"app.test","code":"12345678","expiresAt":(NOW + 60_000) as f64 / 1000.0 - EPOCH_2001,"route":{"privateNetwork":{"host":"mac.local","port":7445}}});
        let link = format!(
            "tether://pair?data={}",
            URL_SAFE_NO_PAD.encode(android.to_string())
        );
        assert_eq!(read(&link, "app.test", NOW).unwrap()["route"]["port"], 7445);
    }

    #[test]
    fn stale_foreign_and_unsafe_invitations_are_refused() {
        let private = json!({"mode":"private","host":"mac.local","port":7445});
        let link = write("app.test", &private, "K7QN4FMB", NOW + 60_000, NOW).unwrap();
        assert_eq!(read(&link, "other.app", NOW), Err("invalid_invitation"));
        assert_eq!(
            read(&link, "app.test", NOW + 61_000),
            Err("invalid_invitation")
        );
        assert!(write("app.test", &private, "K7QN4FMB", NOW + 400_000, NOW).is_err());
        assert_eq!(
            read(&format!("{link}#x"), "app.test", NOW),
            Err("invalid_route")
        );
        for url in [
            "wss://[",
            "wss://[::1",
            "wss://[]",
            "wss://[::1]x",
            "wss://relay]x",
            "wss://relay.example:0",
            "wss://relay.example:99999",
            "ws://relay.example",
            "wss://user@relay.example",
            "wss://relay.example?x=1",
            "https://relay.example",
            "wss://:443",
        ] {
            assert!(
                route(
                    &json!({"mode":"cloud","relayUrl":url,"hostId":"a".repeat(52)}),
                    false
                )
                .is_err(),
                "{url}"
            );
        }
        assert!(route(
            &json!({"mode":"cloud","relayUrl":"ws://127.0.0.1:9000","hostId":"a".repeat(52)}),
            true
        )
        .is_ok());
        assert!(route(&json!({"mode":"private","host":"0.0.0.0","port":1}), false).is_err());
        for url in [
            "wss://relay.example",
            "wss://relay.example:8443/v1/relay",
            "wss://[2001:db8::1]:443",
        ] {
            assert!(
                route(
                    &json!({"mode":"cloud","relayUrl":url,"hostId":"a".repeat(52)}),
                    false
                )
                .is_ok(),
                "{url}"
            );
        }
        assert!(route(
            &json!({"mode":"cloud","relayUrl":"ws://[::1]:9000","hostId":"a".repeat(52)}),
            true
        )
        .is_ok());
    }
}
