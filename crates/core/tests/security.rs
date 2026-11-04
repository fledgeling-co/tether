use tether_core::{
    normalize_code, Error, Identity, NoiseHandshake, Pairing, Role, SecureTransport,
    MAX_CIPHERTEXT, MAX_PLAINTEXT,
};

const APP: &str = "app.example.tool";
const CODE: &str = "K7QN-4FMB";

fn noise() -> (Identity, Identity, NoiseHandshake, NoiseHandshake) {
    let client = Identity::generate().unwrap();
    let host = Identity::generate().unwrap();
    let mut a = NoiseHandshake::initiator(&client, APP).unwrap();
    let mut b = NoiseHandshake::responder(&host, APP).unwrap();
    let one = a.write_message(b"").unwrap();
    b.read_message(&one).unwrap();
    let two = b.write_message(b"").unwrap();
    a.read_message(&two).unwrap();
    let three = a.write_message(b"").unwrap();
    b.read_message(&three).unwrap();
    (client, host, a, b)
}

fn transports() -> (SecureTransport, SecureTransport) {
    let (_, _, a, b) = noise();
    (a.into_transport().unwrap(), b.into_transport().unwrap())
}

#[test]
fn identities_round_trip_and_are_distinct() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();
    assert_ne!(a.public(), b.public());
    assert_eq!(
        a.public(),
        Identity::from_private(a.private()).unwrap().public()
    );
    assert!(matches!(
        Identity::from_private([0; 32]),
        Err(Error::InvalidIdentity)
    ));
}

#[test]
fn noise_knows_both_static_peers_and_identical_finished_transcript() {
    let (client, host, a, b) = noise();
    assert!(a.is_finished() && b.is_finished());
    assert_eq!(a.remote_static(), Some(host.public()));
    assert_eq!(b.remote_static(), Some(client.public()));
    assert_eq!(a.handshake_hash(), b.handshake_hash());
    assert_ne!(a.handshake_hash(), [0; 32]);
}

#[test]
fn noise_different_application_scope_cannot_establish() {
    let identity = Identity::generate().unwrap();
    let mut a = NoiseHandshake::initiator(&identity, APP).unwrap();
    let other = Identity::generate().unwrap();
    let mut b = NoiseHandshake::responder(&other, "app.example.other").unwrap();
    b.read_message(&a.write_message(b"").unwrap()).unwrap();
    let two = b.write_message(b"").unwrap();
    assert!(a.read_message(&two).is_err());
    assert!(matches!(a.write_message(b""), Err(Error::Retired)));
}

#[test]
fn unfinished_or_application_carrying_handshakes_cannot_create_transport() {
    let identity = Identity::generate().unwrap();
    let a = NoiseHandshake::initiator(&identity, APP).unwrap();
    assert!(matches!(a.into_transport(), Err(Error::InvalidState)));
    let mut a = NoiseHandshake::initiator(&identity, APP).unwrap();
    assert_eq!(a.write_message(b"service-open"), Err(Error::EarlyData));
    assert!(matches!(a.into_transport(), Err(Error::Retired)));
}

#[test]
fn authenticated_record_round_trip_is_directional_and_allows_binary_datagrams() {
    let (mut a, mut b) = transports();
    for plain in [vec![], b"hello".to_vec(), vec![0, 255, 1, 0, 42]] {
        let sealed = a.encrypt(&plain).unwrap();
        assert_eq!(b.decrypt(&sealed).unwrap(), plain);
        let reply = b.encrypt(&plain).unwrap();
        assert_eq!(a.decrypt(&reply).unwrap(), plain);
    }
}

#[test]
fn tamper_replay_reorder_and_reflection_are_refused_and_retire_channel() {
    let (mut a, mut b) = transports();
    let sealed = a.encrypt(b"one").unwrap();
    assert_eq!(b.decrypt(&sealed).unwrap(), b"one");
    assert_eq!(b.decrypt(&sealed), Err(Error::Authentication));
    assert_eq!(b.decrypt(&sealed), Err(Error::Retired));

    let (mut a, mut b) = transports();
    let mut tampered = a.encrypt(b"one").unwrap();
    tampered[0] ^= 1;
    assert_eq!(b.decrypt(&tampered), Err(Error::Authentication));

    let (mut a, mut b) = transports();
    let _first = a.encrypt(b"one").unwrap();
    let second = a.encrypt(b"two").unwrap();
    assert_eq!(b.decrypt(&second), Err(Error::Authentication));

    let (mut a, _) = transports();
    let reflected = a.encrypt(b"reflection").unwrap();
    assert_eq!(a.decrypt(&reflected), Err(Error::Authentication));
}

#[test]
fn record_and_handshake_limits_are_enforced() {
    let (mut a, mut b) = transports();
    let maximum = vec![42; MAX_PLAINTEXT];
    let sealed = a.encrypt(&maximum).unwrap();
    assert_eq!(sealed.len(), MAX_CIPHERTEXT);
    assert_eq!(b.decrypt(&sealed).unwrap(), maximum);
    assert_eq!(
        a.encrypt(&vec![0; MAX_PLAINTEXT + 1]),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(
        b.decrypt(&vec![0; MAX_CIPHERTEXT + 1]),
        Err(Error::FrameTooLarge)
    );
    assert_eq!(b.encrypt(b"after oversized frame"), Err(Error::Retired));
    let identity = Identity::generate().unwrap();
    let mut hello = NoiseHandshake::responder(&identity, APP).unwrap();
    assert_eq!(hello.read_message(&vec![0; 513]), Err(Error::FrameTooLarge));
}

#[test]
fn pairing_proves_both_roles_for_the_exact_noise_channel_and_keys() {
    let (client, host, a, b) = noise();
    let (pa, ma) = Pairing::start(
        Role::Client,
        CODE,
        APP,
        a.handshake_hash(),
        client.public(),
        host.public(),
    )
    .unwrap();
    let (pb, mb) = Pairing::start(
        Role::Host,
        CODE,
        APP,
        b.handshake_hash(),
        client.public(),
        host.public(),
    )
    .unwrap();
    let ca = pa.finish(&mb).unwrap();
    let cb = pb.finish(&ma).unwrap();
    ca.verify_peer(&cb.outbound()).unwrap();
    cb.verify_peer(&ca.outbound()).unwrap();
    assert_ne!(ca.outbound(), cb.outbound());
    assert_eq!(ca.verify_peer(&ca.outbound()), Err(Error::Authentication));
    assert_eq!(cb.verify_peer(&cb.outbound()), Err(Error::Authentication));
    assert_eq!(ca.verify_peer(&[0; 31]), Err(Error::Authentication));
}

#[test]
fn wrong_password_app_channel_binding_or_static_identity_never_confirms() {
    let (client, host, a, _) = noise();
    let binding = a.handshake_hash();
    for defect in 0..6 {
        let (pa, ma) = Pairing::start(
            Role::Client,
            CODE,
            APP,
            binding,
            client.public(),
            host.public(),
        )
        .unwrap();
        let mut other_binding = binding;
        let mut other_client = client.public();
        let mut other_host = host.public();
        let mut app = APP;
        let mut password = CODE;
        match defect {
            0 => password = "A7QN4FMB",
            1 => app = "app.example.other",
            2 => other_binding[0] ^= 1,
            3 => other_client[0] ^= 1,
            4 => other_host[0] ^= 1,
            5 => {
                other_client = host.public();
                other_host = client.public();
            }
            _ => unreachable!(),
        }
        let (pb, mb) = Pairing::start(
            Role::Host,
            password,
            app,
            other_binding,
            other_client,
            other_host,
        )
        .unwrap();
        let ca = pa.finish(&mb).unwrap();
        let cb = pb.finish(&ma).unwrap();
        assert_eq!(
            ca.verify_peer(&cb.outbound()),
            Err(Error::Authentication),
            "defect {defect}"
        );
        assert_eq!(
            cb.verify_peer(&ca.outbound()),
            Err(Error::Authentication),
            "defect {defect}"
        );
    }
}

#[test]
fn pairing_malformed_points_side_reflection_and_noncanonical_points_are_refused() {
    for malformed in [
        vec![],
        vec![b'B'; 32],
        vec![b'B'; 34],
        {
            let mut identity = vec![0; 33];
            identity[0] = b'B';
            identity[1] = 1;
            identity
        },
        {
            // y = p+1 is an alternate encoding of the identity; canonical encoding is y=1.
            let mut noncanonical = vec![0xff; 33];
            noncanonical[0] = b'B';
            noncanonical[1] = 0xee;
            noncanonical[32] = 0x7f;
            noncanonical
        },
    ] {
        let (pa, _) = Pairing::start(Role::Client, CODE, APP, [1; 32], [2; 32], [3; 32]).unwrap();
        assert!(pa.finish(&malformed).is_err());
    }
    let (pa, reflection) =
        Pairing::start(Role::Client, CODE, APP, [1; 32], [2; 32], [3; 32]).unwrap();
    assert!(pa.finish(&reflection).is_err());
}

#[test]
fn code_normalization_and_scope_validation_are_bounded() {
    assert_eq!(normalize_code(" k7qn-4fmb ").unwrap(), "K7QN4FMB");
    assert_eq!(normalize_code("oil1-2345").unwrap(), "01112345");
    for invalid in [
        "",
        "1234567",
        "123456789",
        "U2345678",
        "é2345678",
        "K7QN_4FMB",
        "K7QN\n4FMB",
    ] {
        assert_eq!(normalize_code(invalid), Err(Error::InvalidCode));
    }
    for scope in ["", "with space", "scope/other", "scope\nother"] {
        assert!(matches!(
            Pairing::start(Role::Client, CODE, scope, [1; 32], [2; 32], [3; 32]),
            Err(Error::InvalidAppId)
        ));
    }
    assert!(matches!(
        Pairing::start(Role::Client, CODE, APP, [0; 32], [2; 32], [3; 32]),
        Err(Error::InvalidBinding)
    ));
    assert!(matches!(
        Pairing::start(Role::Client, CODE, APP, [1; 32], [2; 32], [2; 32]),
        Err(Error::InvalidIdentity)
    ));
}

#[test]
fn a_tls_terminating_style_split_noise_relay_cannot_relay_pairing_confirmation() {
    // Two real Noise channels represent a terminating proxy, rather than an opaque byte relay.
    let (client, host, client_leg, _) = noise();
    let (_, _, _, host_leg) = noise();
    assert_ne!(client_leg.handshake_hash(), host_leg.handshake_hash());
    let (client_pake, first) = Pairing::start(
        Role::Client,
        CODE,
        APP,
        client_leg.handshake_hash(),
        client.public(),
        host.public(),
    )
    .unwrap();
    let (host_pake, second) = Pairing::start(
        Role::Host,
        CODE,
        APP,
        host_leg.handshake_hash(),
        client.public(),
        host.public(),
    )
    .unwrap();
    let client_confirmation = client_pake.finish(&second).unwrap();
    let host_confirmation = host_pake.finish(&first).unwrap();
    assert_eq!(
        client_confirmation.verify_peer(&host_confirmation.outbound()),
        Err(Error::Authentication)
    );
    assert_eq!(
        host_confirmation.verify_peer(&client_confirmation.outbound()),
        Err(Error::Authentication)
    );
}

#[test]
fn pairing_refuses_off_curve_and_torsion_component_points() {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    let with_torsion = (ED25519_BASEPOINT_POINT + EIGHT_TORSION[1])
        .compress()
        .to_bytes();
    for bytes in [[0xff; 32], with_torsion] {
        let mut malformed = vec![b'B'];
        malformed.extend_from_slice(&bytes);
        let (pake, _) = Pairing::start(Role::Client, CODE, APP, [1; 32], [2; 32], [3; 32]).unwrap();
        assert!(matches!(
            pake.finish(&malformed),
            Err(Error::InvalidMessage)
        ));
    }
}

#[test]
fn application_scope_has_the_same_64_byte_limit_as_the_runtime() {
    let identity = Identity::generate().unwrap();
    assert!(NoiseHandshake::initiator(&identity, &"a".repeat(64)).is_ok());
    assert!(matches!(
        NoiseHandshake::initiator(&identity, &"a".repeat(65)),
        Err(Error::InvalidAppId)
    ));
}
