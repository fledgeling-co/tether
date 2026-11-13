//! The DNS-SD records nearby pairing announces and reads. Each platform browses with its own
//! system API; what goes in a record and what a record means is decided here.
use serde_json::{json, Map, Value};

pub const HOST_SERVICE: &str = "_tether._tcp";
pub const DEVICE_SERVICE: &str = "_tether-dev._tcp";

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

/// A host's invitation to a device, and its parse on the device: one JSON line.
pub fn invite(app_id: &str, host_name: &str, port: u16) -> Value {
    json!({"v": 1, "app": app_id, "port": port, "name": crate::view::label(host_name, "Computer")})
}

pub fn read_invite(app_id: &str, line: &str, remote: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(line.lines().next()?).ok()?;
    let port = value["port"].as_u64().filter(|p| (1..=65535).contains(p))?;
    (value["v"] == 1 && value["app"].as_str() == Some(app_id) && remote.parse::<std::net::IpAddr>().is_ok()).then(|| {
        json!({"host": remote, "port": port, "name": crate::view::label(value["name"].as_str().unwrap_or(""), "Computer")})
    })
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
        let line = invite("test.app", "Studio Mac", 15912).to_string();
        assert_eq!(
            read_invite("test.app", &line, "192.168.1.5").unwrap()["port"],
            15912
        );
        assert!(read_invite("other.app", &line, "192.168.1.5").is_none());
        assert!(read_invite(
            "test.app",
            r#"{"v":1,"app":"test.app","port":0}"#,
            "192.168.1.5"
        )
        .is_none());
        assert!(read_invite("test.app", &line, "not an address").is_none());
    }
}
