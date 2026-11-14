import dnssd
import Foundation
import Network
import Observation

/// Bonjour service types. Hosts announce their direct port; devices announce a small invite
/// listener while their "Add a computer" screen is open, so a host can start the pairing.
public enum TetherNearbyService {
    public static let host = "_tether._tcp"
    public static let device = "_tether-dev._tcp"
}

/// Something found on the local network for this app. Its name is the label it announced and is
/// shown beside the code, never trusted on its own.
public struct TetherNearbyPeer: Identifiable, Hashable, Sendable {
    public let id: String
    public let name: String
    public let kind: String
    /// The public key a host announced. Lets a list mark hosts already paired; the code check
    /// still decides trust.
    public let hostKey: Data?
    /// Addresses and port the announcement listed, tried before a full Bonjour resolve, which can
    /// take many seconds on a Mac with several network interfaces. Hints only; the code decides trust.
    public let addresses: [String]
    public let port: UInt16?
    public let endpoint: NWEndpoint
}

public enum TetherNearbyBrowseState: Equatable, Sendable {
    case searching, ready
    /// Local Network access is off for this app; finding nearby devices needs it.
    case denied
    case failed(String)
}

private func txt(_ record: NWTXTRecord, _ key: String) -> String? {
    guard case let .string(value) = record.getEntry(for: key) else { return nil }
    return value
}

private func cleanLabel(_ raw: String?, fallback: String) -> String {
    TetherCopy.label(raw, fallback: fallback)
}

/// Lists hosts (or devices, on a host) announcing this app on the local network.
@MainActor @Observable
public final class TetherNearbyBrowser {
    public let appID: String
    public let serviceType: String
    public private(set) var peers: [TetherNearbyPeer] = []
    public private(set) var state: TetherNearbyBrowseState = .searching
    @ObservationIgnored private var browser: NWBrowser?
    @ObservationIgnored private let excluding: String?

    /// `excluding` drops this device's own announcement from the list.
    public init(appID: String, serviceType: String = TetherNearbyService.host, excluding: String? = nil) throws {
        try Bridge.validateScope(appID)
        self.appID = appID; self.serviceType = serviceType; self.excluding = excluding
    }

    public func start() {
        guard browser == nil else { return }
        state = .searching
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: serviceType, domain: nil), using: .tcp)
        browser.stateUpdateHandler = { [weak self] update in
            Task { @MainActor in self?.apply(update) }
        }
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            Task { @MainActor in self?.apply(results) }
        }
        self.browser = browser
        browser.start(queue: .main)
    }

    public func stop() {
        browser?.cancel(); browser = nil; peers = []; state = .searching
    }

    private func apply(_ update: NWBrowser.State) {
        switch update {
        case .ready: if state != .denied { state = .ready }
        case let .waiting(error), let .failed(error):
            if case let .dns(code) = error, code == DNSServiceErrorType(kDNSServiceErr_PolicyDenied) {
                state = .denied
            } else if case .failed = update {
                state = .failed("Couldn't look for devices on this network.")
            }
        default: break
        }
    }

    private func apply(_ results: Set<NWBrowser.Result>) {
        if state != .denied { state = .ready }
        peers = results.compactMap { result -> TetherNearbyPeer? in
            guard case let .service(name, _, _, _) = result.endpoint,
                  case let .bonjour(record) = result.metadata,
                  txt(record, "app") == appID, name != excluding else { return nil }
            return TetherNearbyPeer(id: "\(result.endpoint)", name: cleanLabel(txt(record, "name") ?? name, fallback: name),
                                    kind: cleanLabel(txt(record, "kind"), fallback: "Computer"),
                                    hostKey: txt(record, "key").flatMap { Data(base64Encoded: $0) }.flatMap { $0.count == 32 ? $0 : nil },
                                    addresses: (txt(record, "addr") ?? "").split(separator: ",").map(String.init)
                                        .filter { IPv4Address($0) != nil }.prefix(8).map { $0 },
                                    port: txt(record, "port").flatMap { UInt16($0) }.flatMap { $0 > 0 ? $0 : nil },
                                    endpoint: result.endpoint)
        }
        // One announcement shows up once per network interface; list each device once.
        .reduce(into: [String: TetherNearbyPeer]()) { unique, peer in
            let key = peer.name + "|" + (peer.hostKey?.base64EncodedString() ?? "")
            if unique[key] == nil { unique[key] = peer }
        }
        .values.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The address and port behind a Bonjour result, IPv4 first.
    public nonisolated static func route(for peer: TetherNearbyPeer) async throws -> TetherRoute {
        if let port = peer.port {
            for address in peer.addresses where await reachable(address, port: port) {
                return .privateNetwork(host: address, port: port)
            }
        }
        let (host, port) = try await resolve(peer.endpoint)
        return .privateNetwork(host: host, port: port)
    }

    /// Whether a TCP connection to the address opens within a moment.
    nonisolated static func reachable(_ address: String, port: UInt16) async -> Bool {
        guard let target = NWEndpoint.Port(rawValue: port) else { return false }
        let connection = NWConnection(host: NWEndpoint.Host(address), port: target, using: .tcp)
        defer { connection.cancel() }
        return (try? await withTetherDeadline(seconds: 1.5) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Error>) in
                let once = OnceResume(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready: once.resume(returning: true)
                    case .failed, .cancelled: once.resume(returning: false)
                    case .waiting: once.resume(returning: false)
                    default: break
                    }
                }
                connection.start(queue: .global())
            }
        }) ?? false
    }

    nonisolated static func resolve(_ endpoint: NWEndpoint) async throws -> (String, UInt16) {
        let parameters = NWParameters.tcp
        if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options { ip.version = .v4 }
        let connection = NWConnection(to: endpoint, using: parameters)
        defer { connection.cancel() }
        return try await withTetherDeadline(seconds: 25) {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(String, UInt16), Error>) in
                let once = OnceResume(continuation)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        guard case let .hostPort(host, port)? = connection.currentPath?.remoteEndpoint else {
                            once.resume(throwing: TetherClientError.invalidRoute); return
                        }
                        var text: String
                        switch host {
                        case let .ipv4(address): text = "\(address)"
                        case let .ipv6(address): text = "\(address)"
                        case let .name(name, _): text = name
                        @unknown default: text = "\(host)"
                        }
                        if let percent = text.firstIndex(of: "%"), !text.contains(":") { text = String(text[..<percent]) }
                        once.resume(returning: (text, port.rawValue))
                    case let .failed(error): once.resume(throwing: error)
                    case .cancelled: once.resume(throwing: TetherClientError.connectionClosed)
                    default: break
                    }
                }
                connection.start(queue: .global())
            }
        }
    }
}

private final class OnceResume<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Error>?
    init(_ continuation: CheckedContinuation<T, Error>) { self.continuation = continuation }
    func resume(returning value: T) { take()?.resume(returning: value) }
    func resume(throwing error: Error) { take()?.resume(throwing: error) }
    private func take() -> CheckedContinuation<T, Error>? {
        lock.lock(); defer { lock.unlock() }
        let value = continuation; continuation = nil; return value
    }
}

/// A host announcing its existing direct listener. The Rust host owns the socket; this only
/// registers the name, port and app ID with the system's Bonjour responder.
public final class TetherNearbyAnnouncement: @unchecked Sendable {
    private var reference: DNSServiceRef?
    private let queue = DispatchQueue(label: "tether.nearby.announce")

    public init(appID: String, name: String, kind: String, port: UInt16, hostKey: Data? = nil,
                serviceType: String = TetherNearbyService.host) throws
    {
        try Bridge.validateScope(appID)
        // What goes in the record is decided in the core, so every platform announces the same way.
        let response = try Bridge.call(["command": "discovery.txt", "app": appID, "name": name, "kind": kind, "port": Int(port),
                                        "hostKey": hostKey.flatMap { $0.count == 32 ? $0.base64EncodedString() : nil } ?? NSNull(),
                                        "addresses": Self.localIPv4Addresses()])
        guard let entries = response["txt"] as? [String: String] else { throw TetherError.invalidResponse }
        let record = NWTXTRecord(entries)
        let bytes = record.data
        var reference: DNSServiceRef?
        let status = bytes.withUnsafeBytes { raw in
            DNSServiceRegister(&reference, 0, 0, cleanLabel(name, fallback: "Computer"), serviceType, nil, nil,
                               port.bigEndian, UInt16(raw.count), raw.baseAddress, nil, nil)
        }
        guard status == kDNSServiceErr_NoError, let reference else { throw TetherClientError.invalidRoute }
        DNSServiceSetDispatchQueue(reference, queue)
        self.reference = reference
    }

    public func stop() {
        queue.sync { if let reference { DNSServiceRefDeallocate(reference) }; reference = nil }
    }

    /// This computer's IPv4 addresses on interfaces that are up, without loopback or link-local.
    static func localIPv4Addresses() -> [String] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var found: [String] = []
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let entry = pointer.pointee
            guard let address = entry.ifa_addr, address.pointee.sa_family == UInt8(AF_INET),
                  entry.ifa_flags & UInt32(IFF_UP) != 0, entry.ifa_flags & UInt32(IFF_LOOPBACK) == 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            let text = String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            if !text.hasPrefix("169.254."), !found.contains(text) { found.append(text) }
        }
        return found
    }

    deinit { stop() }
}

/// An invitation a host sent to this device's invite listener: connect to this route and pair.
public struct TetherNearbyInvite: Sendable, Equatable {
    public let route: TetherRoute
    public let hostName: String
    /// The one-time token this device issued on the connection the invite arrived over. It is
    /// repeated in `pair.nearby` so the inviting computer can tell this device from any other.
    public let token: String
}

/// A device's invite listener, announced while "Add a computer" is open. An invite only starts
/// an ordinary nearby pairing to the inviting address; the code comparison still decides trust.
///
/// Every connection is answered with a fresh one-time token, and an invite is read only when it
/// echoes that token. So an invite has to come from something that opened a connection to this
/// listener and read a 32-byte secret off it, and each token admits one invite. It does not
/// identify the inviting computer: anything on the local network can open that connection.
public final class TetherNearbyInviteListener: @unchecked Sendable {
    private let listener: NWListener
    private let appID: String

    public init(appID: String, deviceName: String, deviceKind: String,
                onInvite: @escaping @Sendable (TetherNearbyInvite) -> Void) throws
    {
        try Bridge.validateScope(appID)
        self.appID = appID
        let listener = try NWListener(using: .tcp)
        let record = NWTXTRecord(["app": appID, "name": cleanLabel(deviceName, fallback: "Device"), "kind": cleanLabel(deviceKind, fallback: "Device")])
        listener.service = NWListener.Service(name: cleanLabel(deviceName, fallback: "Device"), type: TetherNearbyService.device, txtRecord: record)
        listener.newConnectionHandler = { connection in
            Self.read(connection, appID: appID, onInvite: onInvite)
        }
        self.listener = listener
        listener.start(queue: .global())
    }

    private static func read(_ connection: NWConnection, appID: String, onInvite: @escaping @Sendable (TetherNearbyInvite) -> Void) {
        connection.start(queue: .global())
        // The challenge goes out first: an invite that does not come back carrying this token is
        // not one this device asked for, whatever name it announces.
        guard let token = try? Bridge.call(["command": "discovery.invite_token"])["token"] as? String,
              let challenge = try? Bridge.call(["command": "discovery.challenge", "app": appID, "token": token])["line"] as? String
        else { connection.cancel(); return }
        var line = Data(challenge.utf8)
        line.append(10)
        connection.send(content: line, completion: .contentProcessed { error in
            if error != nil { connection.cancel(); return }
            connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, _ in
                defer { connection.cancel() }
                guard let data, let received = data.split(separator: 10).first,
                      let text = String(data: Data(received), encoding: .utf8),
                      case let .hostPort(host, _)? = connection.currentPath?.remoteEndpoint else { return }
                var remote: String
                switch host {
                case let .ipv4(address): remote = "\(address)"
                case let .ipv6(address): remote = "\(address)"
                case let .name(name, _): remote = name
                @unknown default: return
                }
                if let percent = remote.firstIndex(of: "%"), !remote.contains(":") { remote = String(remote[..<percent]) }
                guard let answer = try? Bridge.call(["command": "discovery.read_invite", "app": appID,
                                                     "line": text, "remote": remote, "token": token]),
                      let invite = answer["invite"] as? [String: Any],
                      let port = invite["port"] as? Int, (1 ... 65535).contains(port),
                      let resolved = invite["host"] as? String
                else { return }
                onInvite(TetherNearbyInvite(route: .privateNetwork(host: resolved, port: UInt16(port)),
                                            hostName: cleanLabel(invite["name"] as? String, fallback: "Computer"),
                                            token: token))
            }
        })
    }

    public func stop() { listener.cancel() }
    deinit { listener.cancel() }

    /// Sent by a host to a device it found: "pair with me at this port". Returns the one-time
    /// token the device issued on this connection, which that device repeats in `pair.nearby`.
    /// Hold it until the request arrives: it is what tells this device's request from another's.
    ///
    /// The device writes its token first, so nothing is sent until one has been read. A peer that
    /// writes no challenge — an older device, or anything else on the port — gets no invite and
    /// this call fails on the deadline rather than waiting.
    @discardableResult
    public static func invite(_ peer: TetherNearbyPeer, appID: String, hostName: String, port: UInt16) async throws -> String {
        try Bridge.validateScope(appID)
        let connection = NWConnection(to: peer.endpoint, using: .tcp)
        // A peer that never writes a challenge must cost a deadline, not the caller. The timeout
        // cancels the connection first, which drives the handler to `.cancelled` and releases the
        // exchange: a deadline that only threw would leave this waiting on a parked continuation.
        return try await withTaskCancellationHandler {
            do {
                let token = try await withThrowingTaskGroup(of: String.self) { group in
                    group.addTask { try await exchange(connection, appID: appID, hostName: hostName, port: port) }
                    group.addTask {
                        try? await Task.sleep(for: .seconds(6))
                        connection.cancel()
                        throw TetherClientError.timeout
                    }
                    defer { group.cancelAll() }
                    guard let first = try await group.next() else { throw TetherClientError.connectionClosed }
                    return first
                }
                connection.cancel()
                return token
            } catch {
                connection.cancel()
                throw error
            }
        } onCancel: {
            connection.cancel()
        }
    }

    /// Reads the device's challenge, then writes the invite echoing its token.
    private static func exchange(_ connection: NWConnection, appID: String, hostName: String, port: UInt16) async throws -> String {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            let once = OnceResume(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, error in
                        guard let data, let received = data.split(separator: 10).first,
                              let challenge = String(data: Data(received), encoding: .utf8),
                              let issued = try? Bridge.call(["command": "discovery.read_challenge", "app": appID,
                                                             "line": challenge])["token"] as? String,
                              let line = try? Bridge.call(["command": "discovery.invite", "app": appID, "name": hostName,
                                                           "port": Int(port), "token": issued])["line"] as? String
                        else { once.resume(throwing: error ?? TetherError.invalidResponse); return }
                        var payload = Data(line.utf8)
                        payload.append(10)
                        connection.send(content: payload, completion: .contentProcessed { sendError in
                            if let sendError { once.resume(throwing: sendError) } else { once.resume(returning: issued) }
                        })
                    }
                case let .failed(error): once.resume(throwing: error)
                case .cancelled: once.resume(throwing: TetherClientError.connectionClosed)
                default: break
                }
            }
            connection.start(queue: .global())
        }
    }
}

/// Where a nearby pairing stands, for the client's sheet.
public enum TetherNearbyPairingState: Equatable, Sendable {
    case idle
    /// Connecting and agreeing the code, usually under a second.
    case checking(peer: String)
    /// Both screens show `code`. `incoming` is true when the computer started it.
    case code(TetherNearbyCode, peer: String, incoming: Bool, expires: Date, otherApproved: Bool)
    /// Approved here; waiting for the computer's owner.
    case waiting(TetherNearbyCode, peer: String)
    /// Both approved and the acknowledgement is going out; it can no longer be cancelled.
    case storing(TetherNearbyCode, peer: String)
    case connected(peer: String, hostID: String)
    case declined(peer: String, byOther: Bool)
    case expired(peer: String)
    case failed(peer: String, message: String)
}

/// Runs one nearby pairing at a time against a connection store, for the client's screens.
@MainActor @Observable
public final class TetherNearbyPairing {
    public private(set) var state: TetherNearbyPairingState = .idle
    @ObservationIgnored private let store: TetherConnectionStore
    @ObservationIgnored private let deviceName: String
    @ObservationIgnored private let deviceKind: String
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var answer: Bool?
    @ObservationIgnored private var shownAt: Date?

    public init(store: TetherConnectionStore, deviceName: String, deviceKind: String) {
        self.store = store; self.deviceName = deviceName; self.deviceKind = deviceKind
    }

    public var isActive: Bool {
        switch state { case .idle, .connected, .declined, .expired, .failed: false; default: true }
    }

    /// Starts pairing with a computer from the list.
    public func start(_ peer: TetherNearbyPeer) {
        begin(peerName: peer.name, incoming: false) { try await TetherNearbyBrowser.route(for: peer) }
    }

    /// Starts pairing with a computer whose address this app already has, such as the Mac it is sharing, without
    /// choosing it from the nearby list. `peerName` is shown beside the code until the computer's own name is known.
    public func start(route: TetherRoute, peerName: String) {
        begin(peerName: peerName, incoming: false) { route }
    }

    /// Starts pairing because a computer invited this device.
    public func accept(_ invite: TetherNearbyInvite) {
        guard !isActive else { return }
        begin(peerName: invite.hostName, incoming: true, inviteToken: invite.token) { invite.route }
    }

    private func begin(peerName: String, incoming: Bool, inviteToken: String? = nil,
                       route: @escaping @Sendable () async throws -> TetherRoute) {
        guard !isActive else { return }
        answer = nil; shownAt = nil
        state = .checking(peer: peerName)
        let store = store, name = deviceName, kind = deviceKind
        task = Task { [weak self] in
            do {
                let route = try await route()
                let outcome = try await store.pairNearby(route: route, deviceName: name, deviceKind: kind,
                    inviteToken: inviteToken,
                    onCode: { code in
                        await MainActor.run {
                            self?.shownAt = Date()
                            self?.state = .code(code, peer: peerName, incoming: incoming,
                                                expires: Date().addingTimeInterval(60), otherApproved: false)
                        }
                    },
                    onHostApproved: {
                        await MainActor.run {
                            if case let .code(code, peer, incoming, expires, _)? = self?.state {
                                self?.state = .code(code, peer: peer, incoming: incoming, expires: expires, otherApproved: true)
                            }
                        }
                    },
                    onStoring: {
                        await MainActor.run {
                            if case let .waiting(code, peer)? = self?.state { self?.state = .storing(code, peer: peer) }
                        }
                    },
                    decision: { await MainActor.run { self?.answer } })
                // Name the new computer as the person chose it, not by its address.
                if case let .paired(host) = outcome, host.displayName != peerName {
                    try? await store.renameHost(hostID: host.id, name: peerName)
                }
                await MainActor.run {
                    switch outcome {
                    case let .paired(host): self?.state = .connected(peer: peerName, hostID: host.id)
                    case .declined: self?.state = .declined(peer: peerName, byOther: self?.answer != false)
                    case .expired: self?.state = .expired(peer: peerName)
                    }
                }
            } catch is CancellationError {
                await MainActor.run { self?.state = .idle }
            } catch {
                await MainActor.run { self?.state = .failed(peer: peerName, message: tetherNearbyMessage(error, peer: peerName)) }
            }
        }
    }

    /// Approve only counts once the code has been on screen for a second, so a stray tap or a
    /// held Return key can't approve a code nobody read.
    public var canApprove: Bool { shownAt.map { Date().timeIntervalSince($0) >= 1 } ?? false }

    public func approve() {
        guard case let .code(code, peer, _, _, _) = state, canApprove else { return }
        answer = true
        state = .waiting(code, peer: peer)
    }

    public func decline() {
        answer = false
    }

    /// Cancels the request; the computer is told it was declined.
    public func cancel() {
        answer = false
    }

    public func reset() {
        task?.cancel(); task = nil; answer = nil; shownAt = nil; state = .idle
    }
}

/// Plain-language explanations for nearby pairing failures.
public func tetherNearbyMessage(_ error: Error, peer: String) -> String {
    TetherCopy.message(for: error, peer: peer)
}
