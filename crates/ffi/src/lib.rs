//! Process-local bounded C ABI. JSON requests/responses may contain secrets; this crate never logs.
//! Handles are local ownership tokens, not an authorization boundary between untrusted callers.
mod media;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    ffi::{c_char, CString},
    sync::{Mutex, OnceLock},
};
use tether_core::{Confirmation, Identity, NoiseHandshake, Pairing, Role, SecureTransport};
use zeroize::{Zeroize, Zeroizing};
const MAX_INPUT: usize = 131_072;
const MAX_HANDLES: usize = 256;

enum Object {
    Identity(Identity),
    Noise(Box<NoiseHandshake>),
    Transport(Box<SecureTransport>),
    Pairing(Box<Pairing>),
    Proof(Confirmation),
}
struct Registry {
    next: u64,
    objects: HashMap<u64, Object>,
}
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            objects: HashMap::new(),
        })
    })
}
impl Registry {
    fn insert(&mut self, object: Object) -> Result<u64, &'static str> {
        if self.objects.len() >= MAX_HANDLES {
            return Err("handle_quota");
        }
        let handle = self.next;
        self.next = self.next.checked_add(1).ok_or("handle_quota")?;
        self.objects.insert(handle, object);
        Ok(handle)
    }
    fn take(&mut self, handle: u64) -> Result<Object, &'static str> {
        self.objects.remove(&handle).ok_or("invalid_handle")
    }
}
struct SensitiveJson(Value);
fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(items) => items.values_mut().for_each(scrub),
        _ => {}
    }
}
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}
fn text<'a>(request: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .ok_or("invalid_request")
}
fn bytes(request: &Value, key: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    STANDARD
        .decode(text(request, key)?)
        .map(Zeroizing::new)
        .map_err(|_| "invalid_base64")
}
fn fixed(request: &Value, key: &str) -> Result<[u8; 32], &'static str> {
    bytes(request, key)?
        .as_slice()
        .try_into()
        .map_err(|_| "invalid_length")
}
fn role(request: &Value) -> Result<Role, &'static str> {
    match text(request, "role")? {
        "client" => Ok(Role::Client),
        "host" => Ok(Role::Host),
        _ => Err("invalid_role"),
    }
}
fn handle(request: &Value) -> Result<u64, &'static str> {
    request
        .get("handle")
        .and_then(Value::as_u64)
        .ok_or("invalid_handle")
}
fn encoded(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}
fn metadata(noise: &NoiseHandshake) -> Value {
    json!({"binding":encoded(noise.handshake_hash()),"remoteStatic":noise.remote_static().map(encoded),"finished":noise.is_finished()})
}
fn perform(request: &Value, registry: &mut Registry) -> Result<Value, &'static str> {
    let command = text(request, "command")?;
    match command {
        "identity.generate" | "identity.fromPrivate" => {
            let identity = if command == "identity.generate" {
                Identity::generate()
            } else {
                Identity::from_private(fixed(request, "private")?)
            }
            .map_err(|_| "crypto_refused")?;
            let private = Zeroizing::new(identity.private());
            let public = identity.public();
            let id = registry.insert(Object::Identity(identity))?;
            Ok(json!({"handle":id,"private":encoded(private.as_ref()),"public":encoded(public)}))
        }
        "noise.new" => {
            let identity_id = request
                .get("identity")
                .and_then(Value::as_u64)
                .ok_or("invalid_handle")?;
            let Some(Object::Identity(identity)) = registry.objects.get(&identity_id) else {
                return Err("invalid_handle");
            };
            let noise = match role(request)? {
                Role::Client => NoiseHandshake::initiator(identity, text(request, "app")?),
                Role::Host => NoiseHandshake::responder(identity, text(request, "app")?),
            }
            .map_err(|_| "crypto_refused")?;
            let id = registry.insert(Object::Noise(Box::new(noise)))?;
            Ok(json!({"handle":id}))
        }
        "noise.write" | "noise.read" => {
            let id = handle(request)?;
            let data = bytes(request, "data")?;
            let Object::Noise(mut noise) = registry.take(id)? else {
                return Err("invalid_handle_type");
            };
            let output = if command == "noise.write" {
                noise.write_message(&data)
            } else {
                noise.read_message(&data)
            }
            .map_err(|_| "crypto_refused")?;
            let mut result = metadata(&noise);
            result["data"] = json!(encoded(output));
            registry.objects.insert(id, Object::Noise(noise));
            Ok(result)
        }
        "noise.finish" => {
            let id = handle(request)?;
            let Object::Noise(noise) = registry.take(id)? else {
                return Err("invalid_handle_type");
            };
            let mut result = metadata(&noise);
            let transport = noise.into_transport().map_err(|_| "crypto_refused")?;
            let next = registry.insert(Object::Transport(Box::new(transport)))?;
            result["handle"] = json!(next);
            Ok(result)
        }
        "transport.encrypt" | "transport.decrypt" => {
            let id = handle(request)?;
            let data = bytes(request, "data")?;
            let Object::Transport(mut transport) = registry.take(id)? else {
                return Err("invalid_handle_type");
            };
            let output = if command == "transport.encrypt" {
                transport.encrypt(&data)
            } else {
                transport.decrypt(&data)
            }
            .map_err(|_| "crypto_refused")?;
            let output = Zeroizing::new(output);
            registry.objects.insert(id, Object::Transport(transport));
            Ok(json!({"data":encoded(output.as_slice())}))
        }
        "pairing.start" => {
            let (pairing, message) = Pairing::start(
                role(request)?,
                text(request, "code")?,
                text(request, "app")?,
                fixed(request, "binding")?,
                fixed(request, "clientKey")?,
                fixed(request, "hostKey")?,
            )
            .map_err(|_| "crypto_refused")?;
            let id = registry.insert(Object::Pairing(Box::new(pairing)))?;
            Ok(json!({"handle":id,"data":encoded(message)}))
        }
        "pairing.finish" => {
            let id = handle(request)?;
            let data = bytes(request, "data")?;
            let Object::Pairing(pairing) = registry.take(id)? else {
                return Err("invalid_handle_type");
            };
            let proof = pairing.finish(&data).map_err(|_| "crypto_refused")?;
            let outbound = proof.outbound();
            let next = registry.insert(Object::Proof(proof))?;
            Ok(json!({"handle":next,"data":encoded(outbound)}))
        }
        "pairing.proof" => {
            let id = handle(request)?;
            let Some(Object::Proof(proof)) = registry.objects.get(&id) else {
                return Err("invalid_handle_type");
            };
            Ok(json!({"data":encoded(proof.outbound())}))
        }
        "pairing.verify" => {
            let id = handle(request)?;
            let data = bytes(request, "data")?;
            let Object::Proof(proof) = registry.take(id)? else {
                return Err("invalid_handle_type");
            };
            proof
                .verify_peer(&data)
                .map_err(|_| "authentication_refused")?;
            Ok(json!({"verified":true}))
        }
        "destroy" => {
            registry.take(handle(request)?)?;
            Ok(json!({}))
        }
        _ => Err("invalid_command"),
    }
}
fn call(input: &[u8]) -> Value {
    let request = match serde_json::from_slice::<Value>(input) {
        Ok(value) if value.is_object() => SensitiveJson(value),
        _ => return json!({"ok":false,"error":"invalid_json"}),
    };
    if request.0["command"]
        .as_str()
        .is_some_and(|command| command.starts_with("media."))
    {
        return match media::perform(&request.0) {
            Ok(mut output) => {
                output["ok"] = json!(true);
                output
            }
            Err(error) => json!({"ok":false,"error":error}),
        };
    }
    let Ok(mut registry) = registry().lock() else {
        return json!({"ok":false,"error":"registry_unavailable"});
    };
    match perform(&request.0, &mut registry) {
        Ok(mut output) => {
            output["ok"] = json!(true);
            output
        }
        Err(error) => {
            if let Ok(id) = handle(&request.0) {
                registry.objects.remove(&id);
            }
            json!({"ok":false,"error":error})
        }
    }
}
fn serialize(value: Value) -> *mut c_char {
    let value = SensitiveJson(value);
    let rendered = Zeroizing::new(value.0.to_string());
    // JSON escapes embedded NULs; an impossible encoding failure returns no caller data.
    CString::new(rendered.as_bytes())
        .unwrap_or_else(|_| CString::default())
        .into_raw()
}
/// Execute a bounded UTF-8 JSON request and return an owned JSON C string.
/// # Safety
/// `request_utf8` must point to `length` readable bytes for the call's duration. The result must
/// be released exactly once by `tether_free`. Neither buffer may be logged.
#[no_mangle]
pub unsafe extern "C" fn tether_call(request_utf8: *const u8, length: usize) -> *mut c_char {
    if request_utf8.is_null() || length == 0 || length > MAX_INPUT {
        return serialize(json!({"ok":false,"error":"invalid_length"}));
    }
    let outcome = std::panic::catch_unwind(|| {
        // SAFETY: the C caller's readable-buffer contract is documented above; length is bounded.
        let input = unsafe { std::slice::from_raw_parts(request_utf8, length) };
        serialize(call(input))
    });
    outcome.unwrap_or_else(|_| serialize(json!({"ok":false,"error":"operation_refused"})))
}
/// Release and wipe a string returned by `tether_call`. NULL is accepted.
/// # Safety
/// A non-null pointer must be a live pointer returned by `tether_call`, passed exactly once.
#[no_mangle]
pub unsafe extern "C" fn tether_free(response: *mut c_char) {
    if response.is_null() {
        return;
    }
    // SAFETY: the C caller must return the exact live allocation once.
    let owned = unsafe { CString::from_raw(response) };
    let mut bytes = owned.into_bytes_with_nul();
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(registry: &mut Registry, value: Value) -> Value {
        perform(&value, registry).expect("test protocol operation")
    }
    #[test]
    fn abi_limits_invalid_utf8_and_null_are_errors_not_unwinds() {
        for (ptr, len) in [
            (std::ptr::null(), 1),
            (b"{}".as_ptr(), MAX_INPUT + 1),
            ([255u8].as_ptr(), 1),
        ] {
            // SAFETY: the oversized request is rejected before reading; other buffers are valid.
            let response = unsafe { tether_call(ptr, len) };
            let decoded: Value = serde_json::from_str(
                unsafe { std::ffi::CStr::from_ptr(response) }
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(decoded["ok"], false);
            unsafe { tether_free(response) };
        }
    }
    #[test]
    fn quota_wrong_types_and_consumed_handles_fail_closed() {
        let mut registry = Registry {
            next: 1,
            objects: HashMap::new(),
        };
        let identity = Identity::generate().unwrap();
        let id = registry.insert(Object::Identity(identity.clone())).unwrap();
        assert!(perform(
            &json!({"command":"noise.finish","handle":id}),
            &mut registry
        )
        .is_err());
        assert!(!registry.objects.contains_key(&id));
        for _ in 0..MAX_HANDLES {
            registry.insert(Object::Identity(identity.clone())).unwrap();
        }
        assert!(registry.insert(Object::Identity(identity)).is_err());
        assert_eq!(registry.objects.len(), MAX_HANDLES);
    }
    #[test]
    fn full_ffi_noise_and_pairing_round_trip() {
        let mut registry = Registry {
            next: 1,
            objects: HashMap::new(),
        };
        let client = request(&mut registry, json!({"command":"identity.generate"}));
        let host = request(&mut registry, json!({"command":"identity.generate"}));
        let a = request(&mut registry,json!({"command":"noise.new","role":"client","identity":client["handle"],"app":"app.test"}))["handle"].clone();
        let b = request(
            &mut registry,
            json!({"command":"noise.new","role":"host","identity":host["handle"],"app":"app.test"}),
        )["handle"]
            .clone();
        for (writer, reader) in [(&a, &b), (&b, &a), (&a, &b)] {
            let out = request(
                &mut registry,
                json!({"command":"noise.write","handle":writer,"data":""}),
            );
            request(
                &mut registry,
                json!({"command":"noise.read","handle":reader,"data":out["data"]}),
            );
        }
        let ta = request(&mut registry, json!({"command":"noise.finish","handle":a}));
        let tb = request(&mut registry, json!({"command":"noise.finish","handle":b}));
        assert_eq!(ta["binding"], tb["binding"]);
        assert_eq!(ta["remoteStatic"], host["public"]);
        let pa = request(
            &mut registry,
            json!({"command":"pairing.start","role":"client","app":"app.test","code":"K7QN4FMB","binding":ta["binding"],"clientKey":client["public"],"hostKey":host["public"]}),
        );
        let pb = request(
            &mut registry,
            json!({"command":"pairing.start","role":"host","app":"app.test","code":"K7QN4FMB","binding":tb["binding"],"clientKey":client["public"],"hostKey":host["public"]}),
        );
        let ca = request(
            &mut registry,
            json!({"command":"pairing.finish","handle":pa["handle"],"data":pb["data"]}),
        );
        let cb = request(
            &mut registry,
            json!({"command":"pairing.finish","handle":pb["handle"],"data":pa["data"]}),
        );
        request(
            &mut registry,
            json!({"command":"pairing.verify","handle":ca["handle"],"data":cb["data"]}),
        );
        request(
            &mut registry,
            json!({"command":"pairing.verify","handle":cb["handle"],"data":ca["data"]}),
        );
        assert!(perform(
            &json!({"command":"pairing.verify","handle":ca["handle"],"data":cb["data"]}),
            &mut registry
        )
        .is_err());
        let cipher = request(
            &mut registry,
            json!({"command":"transport.encrypt","handle":ta["handle"],"data":encoded(b"native interop")}),
        );
        let plain = request(
            &mut registry,
            json!({"command":"transport.decrypt","handle":tb["handle"],"data":cipher["data"]}),
        );
        assert_eq!(plain["data"], encoded(b"native interop"));
    }
}
