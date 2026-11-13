//! What every Tether screen says and enables, so Swift, Compose, WinUI and the browser show the
//! same words and the same rules. Platforms render these view models; they don't write copy.
use serde_json::{json, Value};

/// A label another device chose, made safe to display beside a code: no control characters or
/// direction overrides, trimmed, at most 48 characters.
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

/// The six digits as two groups and as read aloud, digit by digit.
pub fn code(digits: &str) -> Value {
    let (a, b) = digits.split_at(digits.len().min(3));
    let spell = |part: &str| part.chars().map(String::from).collect::<Vec<_>>().join(" ");
    json!({"digits": digits, "groups": [a, b], "spoken": format!("{}, {}", spell(a), spell(b))})
}

/// "Expires in 0:58".
pub fn expiry(remaining_ms: u64) -> String {
    let seconds = remaining_ms.div_ceil(1000);
    format!("Expires in {}:{:02}", seconds / 60, seconds % 60)
}

/// A plain-language explanation for a failure code from any Tether layer.
pub fn error_message(code: &str, peer: &str) -> String {
    capital(&explain(code, peer))
}

fn explain(code: &str, peer: &str) -> String {
    match code {
        "nearby_closed" | "relay_refused" | "nearby_refused" => format!("{peer} isn't accepting new devices right now. Turn on Allow new devices on it, or pair with a code."),
        "paused" | "nearby_paused" => format!("{peer} declined this device several times. Try again in 10 minutes."),
        "busy" | "nearby_busy" => format!("{peer} is already showing another request. Try again in a moment."),
        "already_paired" | "pairing_exists" => format!("This device is already paired with {peer}."),
        "timeout" | "connection_closed" | "unavailable" => format!("{peer} stopped responding. Nothing was paired."),
        "invalid_route" => format!("Couldn't reach {peer} on this network."),
        "identity_mismatch" => "The host identity changed. Verify it with its owner before pairing again.".into(),
        "peer_revoked" => "The host has removed this device's access.".into(),
        "invalid_code" | "authentication_refused" => "That code didn't match. Check the code on the computer and try again.".into(),
        "invalid_invitation" => "That invitation has expired or is for another app. Ask for a new one.".into(),
        "browser_route" => "Browsers can only pair through a cloud relay. Ask for an invitation that uses one.".into(),
        "storage" => "This device couldn't save the pairing. Nothing was paired.".into(),
        _ => "The pairing didn't finish. Nothing was paired.".into(),
    }
}

fn button(label: &str, enabled: bool) -> Value {
    json!({"label": label, "enabled": enabled})
}

/// The requesting device's sheet. `device` is what this device is called in copy ("iPhone",
/// "PC"); `peer` is the computer's announced name.
#[allow(clippy::too_many_arguments)]
pub fn nearby(
    phase: &str,
    peer: &str,
    device: &str,
    incoming: bool,
    digits: Option<&str>,
    remaining_ms: Option<u64>,
    can_approve: bool,
    host_approved: bool,
    declined_by_self: bool,
    error: Option<&str>,
) -> Value {
    let peer = label(peer, "Computer");
    let code_view = digits.map(code);
    let expiry_text = remaining_ms.map(expiry);
    let done = Some(button("Done", true));
    let (title, message, tone, note, primary, secondary, show_code, show_expiry) = match phase {
        "checking" => (format!("Checking the connection to {peer}…"), String::new(), "neutral", None, None, None, false, false),
        "code" => (
            if incoming { format!("{peer} wants to connect") } else { format!("Connect to {peer}?") },
            format!("Check that {peer} shows the same code."),
            "neutral",
            host_approved.then(|| format!("{peer} approved")),
            Some(button("Approve", can_approve)),
            Some(button("Decline", true)),
            true,
            true,
        ),
        "waiting" | "storing" => (
            format!("Approved on this {device}"),
            format!("Waiting for {peer}…"),
            "neutral",
            None,
            None,
            Some(button("Cancel request", phase == "waiting")),
            true,
            false,
        ),
        "connected" => (format!("Connected to {peer}"), format!("{peer} is now in your list."), "success", None, None, None, false, false),
        "declined" => (
            if declined_by_self { "Declined".into() } else { format!("{peer} declined") },
            "Nothing was paired. If the codes were different, another device on this network may have tried to connect.".into(),
            "neutral",
            None,
            done,
            None,
            false,
            false,
        ),
        "expired" => (
            "The request expired".into(),
            "Both devices need to approve within 60 seconds. Try again from the list.".into(),
            "warning",
            None,
            done,
            None,
            false,
            false,
        ),
        _ => ("Couldn't pair".into(), error_message(error.unwrap_or(""), &peer), "warning", None, done, None, false, false),
    };
    json!({
        "phase": phase, "title": title, "message": message, "tone": tone, "note": note,
        "code": if show_code { code_view } else { None },
        "expiry": if show_expiry { expiry_text } else { None },
        "primary": primary, "secondary": secondary,
        // A result replaces the sheet's content, so assistive tech should hear it.
        "announce": matches!(phase, "waiting" | "connected" | "declined" | "expired" | "failed"),
        "busy": matches!(phase, "checking" | "waiting" | "storing"),
    })
}

/// The typed-code sheet. `state` is `entry`, `checking`, `storing` (the ack is going out and it
/// can't be cancelled), `connected` or `failed`; `text` is what the owner has typed so far.
pub fn pair_code(state: &str, peer: &str, text: &str, error: Option<&str>) -> Value {
    let peer = label(peer, "the computer");
    let valid = tether_core::normalize_code(text).is_ok();
    let typed = text.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let hint = (typed > 0
        && !valid
        && (typed >= 8
            || text
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != ' ')))
    .then_some("Codes are 8 letters and numbers, like K7QN-4FMB.");
    let (title, message, tone, primary) = match state {
        "checking" | "storing" => (format!("Pairing with {peer}…"), "Keep the pairing window open on the computer.".to_owned(), "neutral", None),
        "connected" => (format!("Connected to {peer}"), format!("{} is now in your list.", capital(&peer)), "success", Some(button("Done", true))),
        "failed" => ("Couldn't pair".to_owned(), match error.unwrap_or("") {
            // The host drops the connection when its window is closed or the code has expired.
            "connection_closed" | "timeout" => "The computer closed the connection. Check its pairing window is still open, then try again with the code it shows now.".to_owned(),
            code => error_message(code, &peer),
        }, "warning", Some(button("Try again", valid))),
        _ => ("Pair with a code".to_owned(), "Open the pairing window on the computer, then enter the code it shows.".to_owned(), "neutral", Some(button("Pair", valid))),
    };
    json!({
        "state": state, "title": title, "message": message, "tone": tone,
        "field": {"label": "Pairing code", "placeholder": "XXXX-XXXX", "valid": valid, "hint": hint},
        "primary": primary, "secondary": (state != "connected").then(|| button("Cancel", state != "storing")),
        "busy": matches!(state, "checking" | "storing"),
        "announce": matches!(state, "connected" | "failed"),
    })
}

fn capital(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or(String::new(), |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// The host owner's request sheet. `shown_ms` is how long the request has been on screen.
pub fn host_request(
    name: &str,
    digits: &str,
    remaining_ms: u64,
    shown_ms: u64,
    device_approved: bool,
    invited: bool,
    services: &[String],
) -> Value {
    let name = label(name, "Device");
    json!({
        "title": if invited { format!("Connect to {name}?") } else { format!("{name} wants to connect") },
        "code": code(digits),
        "message": format!("Approve only if {name} shows the same code."),
        "services": (!services.is_empty()).then(|| format!("It will be able to use: {}", services.join(", "))),
        "note": device_approved.then(|| format!("{name} approved")),
        "expiry": expiry(remaining_ms),
        "primary": button("Approve", shown_ms >= crate::nearby::READ_MS),
        "secondary": button("Decline", true),
    })
}

/// A saved host's connection state, as every workspace shows it.
pub fn connection_state(state: &str) -> Value {
    let (title, explanation) = match state {
        "connected" => ("Connected", "This host has answered an authenticated status request. Its grants control which services you can use."),
        "connecting" => ("Connecting…", "Checking the saved host identity. Other hosts remain available."),
        "reconnecting" => ("Reconnecting…", "Checking the saved host identity. Other hosts remain available."),
        "revoked" => ("Access removed", "The host no longer permits this device. Ask its owner to open a new pairing window."),
        "identity_mismatch" => ("Host identity changed", "The host key differs from the saved identity. No replacement was accepted. Verify the host with its owner before pairing again."),
        "pending" => ("Pairing interrupted", "Pairing did not finish. Recovery checks the same saved host and device identities."),
        "capacity" => ("Host at capacity", "This host is handling its maximum number of streams. Close a stream or try again shortly."),
        _ => ("Offline", "The host has not answered. Its saved identity is retained. Reconnect when it is available."),
    };
    json!({"state": state, "title": title, "explanation": explanation, "tone": match state { "connected" => "success", "revoked" | "identity_mismatch" => "danger", "pending" | "capacity" => "warning", _ => "neutral" }})
}

/// Fixed copy for the nearby list, the host's Nearby section and the browser, keyed for lookup.
pub fn strings(device: &str) -> Value {
    json!({
        "add_title": "Add a computer",
        "section": "On this network",
        "searching": "Looking for computers with the app open.",
        "empty_title": "No computers found yet",
        "empty_message": "Open the app on your Mac or PC, and check both are on the same network.",
        "footer": "Computers appear while the app is open on them. Choose one, then check that both screens show the same code.",
        "paired": "Paired",
        "manual": "Pair with a code instead",
        "manual_footer": "Use a code to pair through a cloud relay, or with a computer on another network.",
        "denied_title": "Allow Local Network access",
        "denied_message": format!("So this {device} can find computers nearby. Nothing leaves your network."),
        "browser_title": "Pair with a code",
        "browser_message": "Browsers can't look for computers on your network. Open the pairing window on your computer and enter its code, or open its invitation link.",
        "host_section": "Nearby",
        "host_empty": "Phones appear here while they have Add a computer open.",
        "host_footer": "Requests always need your approval here. Each device shows the same code as this computer.",
        "host_allow": "Allow new devices",
        "host_connect": "Connect",
        "host_closed": "Nearby pairing turned off after several unfinished requests. Another device on this network may be trying to connect. Turn Allow new devices back on when you're ready to pair.",
        "workspace_title": "Your hosts",
        "workspace_empty": "Add a Mac or PC to use its services here. You can keep several paired.",
        "services": "Granted services",
        "services_empty": "Services appear after an authenticated connection.",
        "check": "Check connection",
        "recover": "Finish interrupted pairing",
        "discard": "Discard pending pairing",
        "rename": "Rename host",
        "leave": "Leave host",
        "leave_message": "The host forgets this device, and this device forgets the host. Pairing again needs a new code.",
        "forget": "Forget on this device",
        "forget_message": "Only this device forgets the host. The host keeps this device in its list until its owner removes it.",
        "invitation_label": "Invitation link",
        "invitation_placeholder": "tether://pair?data=…",
        "use_invitation": "Use invitation",
        "details": "Enter connection details instead",
        "relay_label": "Relay URL",
        "host_id_label": "Host ID",
        "cancel": "Cancel",
        "done": "Done",
        "save": "Save",
        "name_label": "Name",
        "pairing_busy": "Pairing…",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_codes_and_expiry_format_for_display_and_speech() {
        assert_eq!(label("Field\u{202e}enohPi\n", "Device"), "FieldenohPi");
        assert_eq!(label("  ", "Device"), "Device");
        assert_eq!(code("482913")["groups"], json!(["482", "913"]));
        assert_eq!(code("482913")["spoken"], "4 8 2, 9 1 3");
        assert_eq!(expiry(58_200), "Expires in 0:59");
        assert_eq!(expiry(0), "Expires in 0:00");
    }

    #[test]
    fn the_code_sheet_enables_approve_only_when_the_flow_allows_it() {
        let early = nearby(
            "code",
            "Studio Mac",
            "iPhone",
            false,
            Some("482913"),
            Some(59_000),
            false,
            false,
            false,
            None,
        );
        assert_eq!(early["title"], "Connect to Studio Mac?");
        assert_eq!(early["primary"]["enabled"], false);
        assert_eq!(early["code"]["groups"][1], "913");
        let ready = nearby(
            "code",
            "Studio Mac",
            "iPhone",
            true,
            Some("482913"),
            Some(50_000),
            true,
            true,
            false,
            None,
        );
        assert_eq!(ready["title"], "Studio Mac wants to connect");
        assert_eq!(ready["primary"]["enabled"], true);
        assert_eq!(ready["note"], "Studio Mac approved");
        let waiting = nearby(
            "waiting",
            "Studio Mac",
            "iPhone",
            false,
            Some("482913"),
            None,
            false,
            false,
            false,
            None,
        );
        assert_eq!(waiting["title"], "Approved on this iPhone");
        assert_eq!(waiting["announce"], true);
    }

    #[test]
    fn results_say_who_declined_and_failures_explain_the_code() {
        assert_eq!(
            nearby(
                "declined",
                "Studio Mac",
                "iPhone",
                false,
                None,
                None,
                false,
                false,
                false,
                None
            )["title"],
            "Studio Mac declined"
        );
        assert_eq!(
            nearby(
                "declined",
                "Studio Mac",
                "iPhone",
                false,
                None,
                None,
                false,
                false,
                true,
                None
            )["title"],
            "Declined"
        );
        let paused = nearby(
            "failed",
            "Studio Mac",
            "iPhone",
            false,
            None,
            None,
            false,
            false,
            false,
            Some("paused"),
        );
        assert!(paused["message"].as_str().unwrap().contains("10 minutes"));
        assert_eq!(paused["code"], Value::Null);
    }

    #[test]
    fn the_code_sheet_validates_typing_and_explains_a_closed_window() {
        let empty = pair_code("entry", "", "", None);
        assert_eq!(empty["primary"]["enabled"], false);
        assert_eq!(empty["field"]["hint"], Value::Null);
        assert_eq!(
            pair_code("entry", "", "k7qn-4fmb", None)["primary"]["enabled"],
            true
        );
        assert!(pair_code("entry", "", "K7QN4FMBX", None)["field"]["hint"].is_string());
        let closed = pair_code("failed", "", "K7QN4FMB", Some("connection_closed"));
        assert!(closed["message"]
            .as_str()
            .unwrap()
            .contains("pairing window"));
        assert_eq!(
            pair_code("failed", "", "", Some("already_paired"))["message"],
            "This device is already paired with the computer."
        );
        assert_eq!(
            pair_code("connected", "", "", None)["message"],
            "The computer is now in your list."
        );
        assert_eq!(
            pair_code("checking", "", "", None)["secondary"]["enabled"],
            true
        );
        assert_eq!(
            pair_code("storing", "", "", None)["secondary"]["enabled"],
            false
        );
    }

    #[test]
    fn the_host_sheet_waits_a_second_before_approve() {
        let request = host_request(
            "Field iPhone",
            "482913",
            40_000,
            400,
            false,
            false,
            &["video".into()],
        );
        assert_eq!(request["primary"]["enabled"], false);
        assert_eq!(request["services"], "It will be able to use: video");
        assert_eq!(
            host_request("Field iPhone", "482913", 40_000, 1_000, true, true, &[])["primary"]
                ["enabled"],
            true
        );
    }
}
