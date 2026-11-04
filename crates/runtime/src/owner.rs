//! Owner commands travel only over inherited private pipes or the private Unix socket.
use crate::{carrier::Result, host::Host};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{Read, Write};

pub const MAX_REQUEST: usize = 2048;
pub const MAX_REPLY: usize = 262144;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub v: u8,
    pub request_id: String,
    pub command: String,
    pub expected_app: String,
    pub client_id: Option<String>,
}
pub fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.len() > MAX_REQUEST {
        return Err("owner request exceeds limit".into());
    }
    let request: Request = serde_json::from_slice(bytes)?;
    let id = request.request_id.as_bytes();
    if request.v != 1
        || id.len() != 36
        || !id.iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid owner request".into());
    }
    crate::storage::app_id(&request.expected_app)?;
    if !matches!(
        request.command.as_str(),
        "inspect" | "clients" | "revoke" | "pair-code" | "pairing-status"
    ) || (request.command == "revoke") != request.client_id.is_some()
    {
        return Err("invalid owner command".into());
    }
    Ok(request)
}
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() >= MAX_REPLY {
        return Err("owner reply exceeds limit".into());
    }
    bytes.push(b'\n');
    Ok(bytes)
}
pub fn print(value: &Value) -> Result<()> {
    let bytes = encode(value)?;
    let mut output = std::io::stdout().lock();
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(())
}
pub async fn dispatch(host: Host, request: Request) -> Value {
    let id = request.request_id.clone();
    let result=tokio::task::spawn_blocking(move||->Result<Value>{
        host.owner_scope(&request.expected_app)?;
        match request.command.as_str() {
            "inspect"=>Ok(serde_json::to_value(host.inspect(&request.expected_app)?)?),
            "clients"=>host.owner_clients(&request.expected_app),
            "revoke"=>{host.owner_revoke(&request.expected_app,request.client_id.as_deref().ok_or("missing client")?)?;Ok(json!({}))},
            "pair-code"=>{let code=host.open_pairing()?;let status=host.pairing_status()?;Ok(json!({"code":code,"expires_in_seconds":status.expires_in_seconds,"attempts_remaining":status.attempts_remaining}))},
            "pairing-status"=>Ok(serde_json::to_value(host.pairing_status()?)?),
            _=>Err("invalid owner command".into())
        }
    }).await;
    let response = match result {
        Ok(Ok(payload)) => json!({"event":"reply","request_id":id,"ok":true,"payload":payload}),
        _ => json!({"event":"reply","request_id":id,"ok":false,"error":"owner_command_refused"}),
    };
    if encode(&response).is_err() {
        json!({"event":"reply","request_id":id,"ok":false,"error":"capacity_exceeded"})
    } else {
        response
    }
}
pub struct Input {
    pub closed: tokio::sync::oneshot::Receiver<()>,
    pub commands: tokio::sync::mpsc::Receiver<Request>,
    _keep_open: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::mpsc::Sender<Request>,
    )>,
}
pub fn input(managed: bool, commands: bool) -> Input {
    let (closed, receiver) = tokio::sync::oneshot::channel();
    let (sender, requests) = tokio::sync::mpsc::channel(8);
    if !managed {
        return Input {
            closed: receiver,
            commands: requests,
            _keep_open: Some((closed, sender)),
        };
    }
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        let mut line = Vec::with_capacity(MAX_REQUEST);
        let mut byte = [0];
        loop {
            match input.read(&mut byte) {
                Ok(1) if !commands => {}
                Ok(1) if byte[0] == b'\n' => {
                    let Ok(request) = parse(&line) else {
                        break;
                    };
                    if sender.try_send(request).is_err() {
                        break;
                    }
                    line.clear();
                }
                Ok(1) => {
                    if line.len() >= MAX_REQUEST {
                        break;
                    }
                    line.push(byte[0]);
                }
                _ => break,
            }
        }
        let _ = closed.send(());
    });
    Input {
        closed: receiver,
        commands: requests,
        _keep_open: None,
    }
}
pub async fn serve(host: Host, mut commands: tokio::sync::mpsc::Receiver<Request>) -> Result<()> {
    while let Some(request) = commands.recv().await {
        print(&dispatch(host.clone(), request).await)?;
    }
    futures_util::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_requests_are_exact_scoped_and_bounded() {
        let valid = json!({"v":1,"request_id":"00112233-4455-4677-8899-aabbccddeeff","command":"inspect","expected_app":"test.app"});
        assert!(parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, value) in [
            ("v", json!(2)),
            ("request_id", json!("not-uuid")),
            ("command", json!("shell")),
            ("expected_app", json!("bad/scope")),
            ("client_id", json!("other")),
            ("target", json!("127.0.0.1:8879")),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        assert!(parse(&vec![b' '; MAX_REQUEST + 1]).is_err());
        assert!(encode(&json!({"data":"x".repeat(MAX_REPLY)})).is_err());
    }
}
