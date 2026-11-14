//! The DNS-SD records nearby pairing announces and reads. Each platform browses with its own
//! system API; what goes in a record and what a record means is decided here.
//!
//! An invite is authenticated by a one-time token the *device* mints. A device's invite listener
//! writes [`challenge`] as its first line the moment a connection opens; the inviting host reads
//! it with [`read_challenge`] and must echo that token in its [`invite`]. The device checks the
//! echo with [`read_invite`] and spends the token, and then repeats it in `pair.nearby`, so the
//! host can tell the device it invited from any other device that happens to connect.
//!
//! What that establishes: an invite now has to come from a party that opened a connection to this
//! device's own listener and read a 32-byte secret off it, and each token admits one invite. What
//! it does not establish: the inviting computer's identity. Anything on the local network can
//! still open that connection, so the code comparison remains the only thing that decides trust.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};

pub const HOST_SERVICE: &str = "_tether._tcp";
pub const DEVICE_SERVICE: &str = "_tether-dev._tcp";

/// Bytes of randomness in a one-time invite token.
pub const INVITE_TOKEN_BYTES: usize = 32;
/// Its length once base64url-encoded without padding.
pub const INVITE_TOKEN_LENGTH: usize = 43;
/// The longest line either side of the invite exchange will read.
pub const MAX_INVITE_LINE: usize = 512;

/// A fresh one-time invite token. A device mints one per connection to its invite listener.
pub fn invite_token() -> String {
    let mut bytes = [0u8; INVITE_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Whether a token has the one shape every kit writes.
pub fn token_shape(text: &str) -> bool {
    text.len() == INVITE_TOKEN_LENGTH
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Compares two tokens without leaking how far they matched. Anything misshapen is not a token.
pub fn same_token(left: &str, right: &str) -> bool {
    if !token_shape(left) || !token_shape(right) {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// TXT entries for an announcement. Addresses and the key are hints for speed and for marking
/// paired hosts; the code comparison decides trust.
pub fn txt(
    app_id: &str,
    name: &str,
    kind: &str,
    port: u16,
    host_key: Option<&str>,
    addresses: &[String],
) -> Value {
    let mut entries = Map::new();
    entries.insert("app".into(), app_id.into());
    entries.insert("name".into(), crate::view::label(name, "Computer").into());
    entries.insert("kind".into(), crate::view::label(kind, "Computer").into());
    entries.insert("port".into(), port.to_string().into());
    if let Some(key) = host_key.filter(|key| key.len() == 44) {
        entries.insert("key".into(), key.into());
    }
    let listed: Vec<&str> = addresses
        .iter()
        .map(String::as_str)
        .filter(|a| ipv4(a))
        .take(6)
        .collect();
    if !listed.is_empty() {
        entries.insert("addr".into(), listed.join(",").into());
    }
    Value::Object(entries)
}

fn ipv4(text: &str) -> bool {
    text.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
}

/// A browse result as a peer for this app, or `None` when it belongs to another app. `txt` is the
/// record's entries; `resolved` and `port` are what the system resolver found, if anything.
pub fn peer(
    app_id: &str,
    id: &str,
    service_name: &str,
    txt: &Value,
    resolved: &[String],
    port: u16,
) -> Option<Value> {
    if txt["app"].as_str() != Some(app_id) {
        return None;
    }
    let mut addresses: Vec<String> = txt["addr"]
        .as_str()
        .unwrap_or("")
        .split(',')
        .filter(|a| ipv4(a))
        .map(str::to_owned)
        .collect();
    addresses.extend(resolved.iter().filter(|a| ipv4(a)).cloned());
    addresses.dedup();
    let mut seen = std::collections::HashSet::new();
    addresses.retain(|a| seen.insert(a.clone()));
    addresses.truncate(8);
    // No port in the record or from a resolve yet means the caller resolves the service itself.
    let port = txt["port"]
        .as_str()
        .and_then(|p| p.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(port);
    let key = txt["key"].as_str().filter(|k| k.len() == 44);
    Some(json!({
        "id": id,
        "name": crate::view::label(txt["name"].as_str().unwrap_or(service_name), &crate::view::label(service_name, "Computer")),
        "kind": crate::view::label(txt["kind"].as_str().unwrap_or(""), "Computer"),
        "host_key": key,
        "addresses": addresses,
        "port": (port > 0).then_some(port),
    }))
}

/// The first line a device's invite listener writes: the one-time token for this connection.
pub fn challenge(app_id: &str, token: &str) -> Result<Value, &'static str> {
    if !token_shape(token) {
        return Err("invalid_token");
    }
    Ok(json!({"v": 1, "app": app_id, "tok": token}))
}

/// Reads a challenge line on the inviting host, returning the token the invite must echo.
pub fn read_challenge(app_id: &str, line: &str) -> Option<String> {
    let value: Value = serde_json::from_str(first_line(line)?).ok()?;
    let token = value["tok"].as_str().filter(|t| token_shape(t))?;
    (value["v"] == 1 && value["app"].as_str() == Some(app_id)).then(|| token.to_owned())
}

/// A host's invitation to a device, echoing the token that device just issued: one JSON line.
pub fn invite(
    app_id: &str,
    host_name: &str,
    port: u16,
    token: &str,
) -> Result<Value, &'static str> {
    if !token_shape(token) {
        return Err("invalid_token");
    }
    Ok(
        json!({"v": 1, "app": app_id, "port": port, "name": crate::view::label(host_name, "Computer"), "tok": token}),
    )
}

/// The device's read of an invite. `issued` is the token this listener minted for this
/// connection; an invite that does not echo it is not one this device asked for.
pub fn read_invite(app_id: &str, line: &str, remote: &str, issued: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(first_line(line)?).ok()?;
    let port = value["port"].as_u64().filter(|p| (1..=65535).contains(p))?;
    let echoed = value["tok"].as_str().unwrap_or("");
    (value["v"] == 1
        && value["app"].as_str() == Some(app_id)
        && same_token(echoed, issued)
        && remote.parse::<std::net::IpAddr>().is_ok())
    .then(|| {
        json!({"host": remote, "port": port, "name": crate::view::label(value["name"].as_str().unwrap_or(""), "Computer"), "token": issued})
    })
}

/// The first line of a bounded read. Anything longer than a line either side will write is not
/// one of ours, so it is refused rather than truncated into something that parses.
fn first_line(text: &str) -> Option<&str> {
    let line = text.lines().next()?;
    (line.len() <= MAX_INVITE_LINE).then_some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip_and_ignore_other_apps_and_bad_hints() {
        let entries = txt(
            "dev.simdeck.app",
            "Studio Mac",
            "Mac",
            15912,
            Some(&"k".repeat(44)),
            &["192.168.1.5".into(), "127.0.0.1".into(), "fe80::1".into()],
        );
        assert_eq!(entries["addr"], "192.168.1.5");
        let found = peer(
            "dev.simdeck.app",
            "x",
            "Studio Mac",
            &entries,
            &["192.168.1.5".into(), "10.0.0.2".into()],
            0,
        )
        .unwrap();
        assert_eq!(found["addresses"], json!(["192.168.1.5", "10.0.0.2"]));
        assert_eq!(found["port"], 15912);
        assert!(peer("other.app", "x", "Studio Mac", &entries, &[], 0).is_none());
        let bare = peer(
            "dev.simdeck.app",
            "y",
            "Old Mac",
            &json!({"app":"dev.simdeck.app"}),
            &[],
            0,
        )
        .unwrap();
        assert_eq!(bare["port"], Value::Null);
        assert_eq!(bare["name"], "Old Mac");
    }

    #[test]
    fn invites_are_scoped_to_the_app_and_need_a_real_port() {
        let token = invite_token();
        let line = invite("test.app", "Studio Mac", 15912, &token)
            .unwrap()
            .to_string();
        assert_eq!(
            read_invite("test.app", &line, "192.168.1.5", &token).unwrap()["port"],
            15912
        );
        assert!(read_invite("other.app", &line, "192.168.1.5", &token).is_none());
        assert!(read_invite(
            "test.app",
            &json!({"v":1,"app":"test.app","port":0,"tok":token}).to_string(),
            "192.168.1.5",
            &token
        )
        .is_none());
        assert!(read_invite("test.app", &line, "not an address", &token).is_none());
    }

    #[test]
    fn an_invite_is_refused_unless_it_echoes_the_token_this_device_issued() {
        let issued = invite_token();
        let other = invite_token();
        assert_ne!(issued, other);
        let honest = invite("test.app", "Studio Mac", 15912, &issued)
            .unwrap()
            .to_string();
        let read = read_invite("test.app", &honest, "192.168.1.5", &issued).unwrap();
        assert_eq!(read["token"], issued, "the device echoes it in pair.nearby");

        // The defect this closes: a line anybody on the network could compose.
        let unauthenticated = json!({"v":1,"app":"test.app","port":15912,"name":"Studio Mac"});
        assert!(
            read_invite(
                "test.app",
                &unauthenticated.to_string(),
                "192.168.1.5",
                &issued
            )
            .is_none(),
            "an invite with no token is not one this device asked for"
        );
        // Somebody else's live token, and a guess of the right shape, are both refused.
        let foreign = invite("test.app", "Studio Mac", 15912, &other)
            .unwrap()
            .to_string();
        assert!(read_invite("test.app", &foreign, "192.168.1.5", &issued).is_none());
        let guess =
            json!({"v":1,"app":"test.app","port":15912,"tok":"A".repeat(INVITE_TOKEN_LENGTH)});
        assert!(read_invite("test.app", &guess.to_string(), "192.168.1.5", &issued).is_none());
        // The same invite read against a spent token: the listener mints one per connection,
        // so a replay has no issued token left to match.
        assert!(read_invite("test.app", &honest, "192.168.1.5", &invite_token()).is_none());
        // A misshapen issued token can never admit anything, so a caller cannot opt out.
        assert!(read_invite("test.app", &honest, "192.168.1.5", "").is_none());
        assert!(invite("test.app", "Studio Mac", 15912, "short").is_err());
    }

    #[test]
    fn a_challenge_carries_one_token_and_is_read_only_for_this_app() {
        let token = invite_token();
        assert!(token_shape(&token));
        assert_eq!(token.len(), INVITE_TOKEN_LENGTH);
        let line = challenge("test.app", &token).unwrap().to_string();
        assert_eq!(read_challenge("test.app", &line), Some(token.clone()));
        assert_eq!(read_challenge("other.app", &line), None);
        assert_eq!(
            read_challenge(
                "test.app",
                &json!({"v":2,"app":"test.app","tok":token}).to_string()
            ),
            None
        );
        assert_eq!(
            read_challenge("test.app", &json!({"v":1,"app":"test.app"}).to_string()),
            None
        );
        assert!(challenge("test.app", "nope").is_err());
        // Two mints never collide, and a line longer than either side writes is refused.
        assert_ne!(invite_token(), invite_token());
        assert_eq!(
            read_challenge("test.app", &" ".repeat(MAX_INVITE_LINE + 1)),
            None
        );
    }

    #[test]
    fn tokens_compare_whole_and_refuse_anything_misshapen() {
        let token = invite_token();
        assert!(same_token(&token, &token.clone()));
        assert!(!same_token(&token, &invite_token()));
        let mut altered = token.clone().into_bytes();
        altered[INVITE_TOKEN_LENGTH - 1] ^= 1;
        let altered = String::from_utf8(altered).unwrap();
        assert!(
            !same_token(&token, &altered),
            "a token differing only in its last character"
        );
        assert!(!same_token("", ""));
        assert!(!token_shape(&format!("{}+", &token[1..])));
    }
}
