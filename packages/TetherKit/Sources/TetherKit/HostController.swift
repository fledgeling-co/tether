#if os(macOS)
    import Darwin
    import Foundation
    import Observation

    public enum TetherHostControllerError: Error, Sendable {
        case helperUnavailable, helperFailed, invalidProfile, invalidStatus, alreadyRunning, operationInProgress
    }

    /// The owner registers fixed loopback targets. Remote peers only ever select a service ID.
    public struct TetherHostServiceProfile: Equatable, Sendable {
        public let id: String
        public let kind: TetherServiceKind
        public let loopbackAddress: String
        public let port: UInt16
        /// A private file holding a 32-byte key the service also holds. When set, the host proves
        /// the connecting device to the service before forwarding: the service sends a challenge
        /// and the host answers with the device's public key and an HMAC under this key. TCP only.
        public let identityKeyFile: URL?
        public init(id: String, kind: TetherServiceKind, loopbackAddress: String = "127.0.0.1", port: UInt16,
                    identityKeyFile: URL? = nil) throws {
            try Bridge.validateScope(id)
            guard port > 0, ["127.0.0.1", "::1"].contains(loopbackAddress),
                  identityKeyFile == nil || (kind == .tcp && identityKeyFile?.isFileURL == true) else {
                throw TetherHostControllerError.invalidProfile
            }
            self.id = id; self.kind = kind; self.loopbackAddress = loopbackAddress; self.port = port
            self.identityKeyFile = identityKeyFile
        }

        var argument: String {
            "\(id)=\(kind.rawValue)://\(loopbackAddress == "::1" ? "[::1]" : loopbackAddress):\(port)"
        }

        var identityArguments: [String] {
            identityKeyFile.map { ["--identify", "\(id)=\($0.path)"] } ?? []
        }
    }

    public enum TetherHostRoute: Equatable, Sendable {
        case privateNetwork(address: String, port: UInt16)
        case cloud(relayURL: URL)

        func arguments() throws -> [String] {
            switch self {
            case .privateNetwork: return try ["--direct", socketAddress()]
            case let .cloud(url):
                guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.scheme == "wss",
                      parts.host?.isEmpty == false, parts.user == nil, parts.password == nil,
                      parts.query == nil, parts.fragment == nil, url.absoluteString.utf8.count <= 2048
                else {
                    throw TetherHostControllerError.invalidProfile
                }
                return ["--relay", url.absoluteString]
            }
        }

        func socketAddress() throws -> String {
            guard case let .privateNetwork(address, port) = self, port > 0 else {
                throw TetherHostControllerError.invalidProfile
            }
            var ipv4 = in_addr(); var ipv6 = in6_addr()
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let capacity = socklen_t(buffer.count)
            let v6: Bool
            if inet_pton(AF_INET, address, &ipv4) == 1 {
                guard inet_ntop(AF_INET, &ipv4, &buffer, capacity) != nil else {
                    throw TetherHostControllerError.invalidProfile
                }
                v6 = false
            } else if inet_pton(AF_INET6, address, &ipv6) == 1 {
                guard inet_ntop(AF_INET6, &ipv6, &buffer, capacity) != nil else {
                    throw TetherHostControllerError.invalidProfile
                }
                v6 = true
            } else {
                throw TetherHostControllerError.invalidProfile
            }
            let host = String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
            return "\(v6 ? "[\(host)]" : host):\(port)"
        }
    }

    public enum TetherHostState: Equatable, Sendable {
        case stopped, starting, listening(address: String), relayConnected(hostID: String), relayDisconnected, failed
    }

    public struct TetherHostClient: Codable, Equatable, Identifiable, Sendable {
        public var id: String {
            device
        }

        public let device: String
        /// The label the device gave when it paired nearby; nil for devices paired with a code.
        public let name: String?
        public let services: [String]
        /// Current authenticated channels, including control channels, observed by the running helper.
        public let activeSessions: Int?
        public let recentlySeen: Bool?
        public let lastSeenUnixMilliseconds: UInt64?
        enum CodingKeys: String, CodingKey {
            case device, name, services
            case activeSessions = "active_sessions"
            case recentlySeen = "recently_seen"
            case lastSeenUnixMilliseconds = "last_seen_unix_ms"
        }

        public init(device: String, name: String? = nil, services: [String], activeSessions: Int? = nil, recentlySeen: Bool? = nil,
                    lastSeenUnixMilliseconds: UInt64? = nil)
        {
            self.device = device; self.name = name; self.services = services; self.activeSessions = activeSessions
            self.recentlySeen = recentlySeen; self.lastSeenUnixMilliseconds = lastSeenUnixMilliseconds
        }
    }

    struct HostDescription: Decodable, Sendable {
        let app_id: String
        let host_id: String
        let host_key: String?
        let services: [TetherHostService]
    }

    struct HostEvent: Decodable, Sendable {
        let event: String
        let id: String?
        let address: String?
    }

    protocol HostHelper: Sendable {
        func execute(_ arguments: [String]) async throws -> Data
        func start(_ arguments: [String]) async throws -> AsyncThrowingStream<HostEvent, Error>
        func request(command: String, expectedApp: String, clientID: String?) async throws -> Data
        func request(command: String, expectedApp: String, fields: [String: any Sendable]) async throws -> Data
        func stop() async -> Bool
        func processIdentifier() async -> Int32?
    }

    extension HostHelper {
        func processIdentifier() async -> Int32? { nil }

        /// Owner commands that carry extra fields; helpers without them refuse.
        func request(command: String, expectedApp: String, fields: [String: any Sendable]) async throws -> Data {
            guard fields.isEmpty else { throw TetherHostControllerError.helperFailed }
            return try await request(command: command, expectedApp: expectedApp, clientID: nil)
        }
    }

    /// A device waiting for this host's owner to compare its code and approve or decline.
    public struct TetherNearbyRequest: Identifiable, Equatable, Sendable {
        public let id: UInt64
        public let name: String
        public let kind: String
        public let code: TetherNearbyCode
        public let expiresAt: Date
        /// The device's owner has already approved the same code.
        public let deviceApproved: Bool
        /// The one-time token this device echoed from an invite, when it answered one. Compare it
        /// against the token `invite(_:hostName:)` returned to tell the device this Mac invited
        /// from any other device that happens to be pairing; an announced name is not evidence.
        public let inviteToken: String?
    }

    /// Owns the helper's stdin and lifetime. It reads only safe helper output, never the private
    /// host configuration. The executable URL is fixed at initialization and no shell is invoked.
    @MainActor @Observable
    public final class TetherHostController {
        public let appID: String
        public private(set) var state: TetherHostState = .stopped
        public private(set) var clients: [TetherHostClient] = []
        public private(set) var services: [TetherHostService] = []
        public private(set) var hostID: String?
        /// This host's public key, announced so nearby devices can show it as already paired.
        public private(set) var hostKey: Data?
        public private(set) var pairingCode: String?
        public private(set) var pairingExpiresAt: Date?
        public private(set) var pairingAttemptsRemaining: Int?
        /// Requests from nearby devices, newest last. Each shows the code both screens display.
        public private(set) var nearbyRequests: [TetherNearbyRequest] = []
        /// Whether nearby devices may ask to pair. Requests always need the owner's approval.
        public private(set) var allowsNearby = true
        /// Set when the host closed nearby pairing itself after unfinished requests, which is what
        /// a device in the middle trying for a matching code looks like.
        public private(set) var nearbyClosedForSafety = false
        @ObservationIgnored private var nearbyWatch: Task<Void, Never>?
        @ObservationIgnored private var announcement: TetherNearbyAnnouncement?
        @ObservationIgnored private var nearbyPort: UInt16?
        @ObservationIgnored private var ownerActive = false
        @ObservationIgnored private let config: URL
        @ObservationIgnored private let helper: any HostHelper
        @ObservationIgnored private var launch: Task<AsyncThrowingStream<HostEvent, Error>, Error>?
        @ObservationIgnored private var observer: Task<Void, Never>?
        @ObservationIgnored private var presence: Task<Void, Never>?
        @ObservationIgnored private var expiry: Task<Void, Never>?
        @ObservationIgnored private var generation = UUID()
        @ObservationIgnored private var pairingGeneration = UUID()
        @ObservationIgnored private var busy = false

        public convenience init(helperURL: URL, configurationURL: URL, appID: String) throws {
            guard helperURL.isFileURL, helperURL.path.hasPrefix("/"),
                  FileManager.default.isExecutableFile(atPath: helperURL.path)
            else {
                throw TetherHostControllerError.helperUnavailable
            }
            try self.init(helper: ProcessHostHelper(executable: helperURL), configurationURL: configurationURL, appID: appID)
        }

        init(helper: any HostHelper, configurationURL: URL, appID: String) throws {
            try Bridge.validateScope(appID)
            guard configurationURL.isFileURL, configurationURL.path.hasPrefix("/"),
                  configurationURL.path.utf8.count <= 4096 else { throw TetherHostControllerError.invalidProfile }
            self.helper = helper; config = configurationURL; self.appID = appID
        }

        deinit { launch?.cancel(); observer?.cancel(); presence?.cancel(); expiry?.cancel(); nearbyWatch?.cancel(); announcement?.stop() }

        public func initialize(services profiles: [TetherHostServiceProfile]) async throws {
            try begin(); defer { busy = false }
            guard state == .stopped, !profiles.isEmpty, profiles.count <= 32,
                  Set(profiles.map(\.id)).count == profiles.count else { throw TetherHostControllerError.invalidProfile }
            let arguments = ["host", "init", "--config", config.path, "--app", appID]
                + profiles.flatMap { ["--service", $0.argument] }
                + profiles.flatMap(\.identityArguments)
            _ = try await helper.execute(arguments)
            try await inspect()
        }

        public func start(route: TetherHostRoute) async throws {
            try begin(); defer { busy = false }
            guard state == .stopped || state == .failed else { throw TetherHostControllerError.alreadyRunning }
            let routeArguments = try route.arguments()
            try await inspect()
            let token = UUID(); generation = token
            state = .starting
            do {
                let arguments = scoped("run") + routeArguments + ["--status-json", "--managed-stdin"]
                let helper = helper
                let launching = Task { try await helper.start(arguments) }
                launch = launching
                let events = try await withTaskCancellationHandler { try await launching.value }
                    onCancel: { launching.cancel() }
                launch = nil
                try Task.checkCancellation()
                guard generation == token else { throw CancellationError() }
                ownerActive = true
                startPresenceObservation(token: token)
                if case let .privateNetwork(_, port) = route { nearbyPort = port }
                startNearbyObservation(token: token)
                observer = Task { [weak self] in
                    do {
                        for try await event in events {
                            guard !Task.isCancelled, self?.generation == token else { return }
                            try self?.apply(event, route: route)
                        }
                        if !Task.isCancelled, self?.generation == token {
                            self?.state = .failed; self?.clearCode(); self?.clearPresence(); self?.ownerActive = false
                            _ = await helper.stop()
                        }
                    } catch {
                        if !Task.isCancelled, self?.generation == token {
                            self?.state = .failed; self?.clearCode(); self?.clearPresence(); self?.ownerActive = false
                            _ = await helper.stop()
                        }
                    }
                }
            } catch {
                launch = nil
                if generation == token {
                    state = .failed; ownerActive = false; _ = await helper.stop()
                }
                throw error
            }
        }

        public func stop() async {
            generation = UUID(); launch?.cancel(); launch = nil; observer?.cancel(); observer = nil
            clearCode(); clearPresence(); presence?.cancel(); presence = nil; ownerActive = false
            stopNearby()
            let exited = await helper.stop()
            state = exited ? .stopped : .failed
        }

        public func openPairingWindow() async throws {
            try begin(); defer { busy = false }
            guard transportReady else { throw TetherHostControllerError.helperFailed }
            try await inspect()
            let token = generation
            let output = try await helper.request(command: "pair-code", expectedApp: appID, clientID: nil)
            struct Window: Decodable { let code: String; let expires_in_seconds: Int; let attempts_remaining: Int }
            guard generation == token, ownerActive, transportReady else { throw CancellationError() }
            let window = try JSONDecoder().decode(Window.self, from: output)
            let code = window.code
            guard code.utf8.count == 8,
                  code.utf8.allSatisfy({ "0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8.contains($0) }),
                  (1 ... 300).contains(window.expires_in_seconds), (0 ... 3).contains(window.attempts_remaining)
            else {
                throw TetherHostControllerError.invalidStatus
            }
            clearCode()
            pairingCode = code; pairingExpiresAt = Date().addingTimeInterval(Double(window.expires_in_seconds))
            pairingAttemptsRemaining = window.attempts_remaining
            let windowID = pairingGeneration
            let deadline = ContinuousClock.now.advanced(by: .seconds(window.expires_in_seconds))
            expiry = Task { [weak self] in
                while !Task.isCancelled, ContinuousClock.now < deadline {
                    do {
                        try await Task.sleep(for: .seconds(2))
                        guard let self, self.pairingGeneration == windowID else { return }
                        try await self.refreshWindow(windowID: windowID)
                    } catch {
                        if !Task.isCancelled, self?.pairingGeneration == windowID {
                            self?.clearCode()
                        }
                        return
                    }
                }
                if self?.pairingGeneration == windowID {
                    self?.clearCode()
                }
            }
        }

        private func refreshWindow(windowID: UUID) async throws {
            let output = try await helper.request(command: "pairing-status", expectedApp: appID, clientID: nil)
            guard pairingGeneration == windowID, ownerActive else { return }
            struct Status: Decodable { let open: Bool; let expires_in_seconds: Int; let attempts_remaining: Int }
            let status = try JSONDecoder().decode(Status.self, from: output)
            guard (0 ... 300).contains(status.expires_in_seconds), (0 ... 3).contains(status.attempts_remaining) else {
                throw TetherHostControllerError.invalidStatus
            }
            if !status.open || status.expires_in_seconds == 0 || status.attempts_remaining == 0 {
                clearCode(); return
            }
            pairingExpiresAt = Date().addingTimeInterval(Double(status.expires_in_seconds))
            pairingAttemptsRemaining = status.attempts_remaining
        }

        /// Announces this host to nearby devices on its private-network port. The name is what
        /// phones list, so use the computer's own name.
        public func announceNearby(name: String, kind: String = "Mac") throws {
            guard let nearbyPort, ownerActive else { throw TetherHostControllerError.helperFailed }
            announcement?.stop()
            announcement = try TetherNearbyAnnouncement(appID: appID, name: name, kind: kind, port: nearbyPort, hostKey: hostKey)
        }

        /// Invites a device from the nearby list. It connects back and both screens show the code.
        /// Invites a nearby device. Returns the one-time token that device issued; a request
        /// carrying it is the one that answered this invite.
        @discardableResult
        public func invite(_ peer: TetherNearbyPeer, hostName: String) async throws -> String {
            guard let nearbyPort, ownerActive, allowsNearby else { throw TetherHostControllerError.helperFailed }
            return try await TetherNearbyInviteListener.invite(peer, appID: appID, hostName: hostName, port: nearbyPort)
        }

        public func decideNearby(_ request: TetherNearbyRequest, approve: Bool) async throws {
            guard ownerActive else { throw TetherHostControllerError.helperFailed }
            _ = try await helper.request(command: "nearby-decide", expectedApp: appID,
                                         fields: ["nearby_id": request.id, "approve": approve])
            nearbyRequests.removeAll { $0.id == request.id }
            if approve, !request.deviceApproved { try? await refreshNearby() }
        }

        public func setAllowsNearby(_ allow: Bool) async throws {
            guard ownerActive else { throw TetherHostControllerError.helperFailed }
            _ = try await helper.request(command: "nearby-allow", expectedApp: appID, fields: ["approve": allow])
            allowsNearby = allow
            if allow { nearbyClosedForSafety = false } else { nearbyRequests = [] }
        }

        private func startNearbyObservation(token: UUID) {
            nearbyWatch?.cancel()
            nearbyWatch = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self, self.generation == token, self.ownerActive else { return }
                    try? await self.refreshNearby()
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }

        private func refreshNearby() async throws {
            let output = try await helper.request(command: "nearby", expectedApp: appID, fields: [:])
            struct Listing: Decodable {
                struct Item: Decodable {
                    let id: UInt64; let name: String; let kind: String; let code: String
                    let expires_in_seconds: Int; let client_approved: Bool; let decision: Bool?
                    let invite_token: String?
                }
                let allow: Bool; let closed: String?; let requests: [Item]
            }
            let listing = try JSONDecoder().decode(Listing.self, from: output)
            allowsNearby = listing.allow
            nearbyClosedForSafety = listing.closed != nil
            nearbyRequests = listing.requests.prefix(4).compactMap { item in
                guard item.decision == nil, let code = TetherNearbyCode(digits: item.code),
                      (0 ... 60).contains(item.expires_in_seconds) else { return nil }
                return TetherNearbyRequest(id: item.id, name: String(item.name.prefix(48)), kind: String(item.kind.prefix(48)),
                                           code: code, expiresAt: Date().addingTimeInterval(Double(item.expires_in_seconds)),
                                           deviceApproved: item.client_approved,
                                           inviteToken: item.invite_token)
            }
        }

        private func stopNearby() {
            nearbyWatch?.cancel(); nearbyWatch = nil
            announcement?.stop(); announcement = nil
            nearbyRequests = []; nearbyPort = nil
        }

        /// The running host process. Its services reach the app's loopback targets from this
        /// process, so an app can refuse loopback connections that come from anywhere else.
        public func hostProcessIdentifier() async -> Int32? {
            guard ownerActive else { return nil }
            return await helper.processIdentifier()
        }

        public func refreshClients() async throws {
            try begin(); defer { busy = false }
            try await inspect()
            try await loadClients()
        }

        public func revoke(clientID: String) async throws {
            try begin(); defer { busy = false }
            guard clientID.utf8.count == 64, clientID.utf8.allSatisfy({ "0123456789abcdef".utf8.contains($0) }) else {
                throw TetherHostControllerError.invalidProfile
            }
            try await inspect()
            if ownerActive {
                _ = try await helper.request(command: "revoke", expectedApp: appID, clientID: clientID)
            } else {
                _ = try await helper.execute(scoped("revoke") + ["--device", clientID])
            }
            try await loadClients()
        }

        private func inspect() async throws {
            let token = generation
            let output = try await ownerCommand("inspect", cli: "inspect")
            guard generation == token else { throw CancellationError() }
            let value = try JSONDecoder().decode(HostDescription.self, from: output)
            guard value.app_id == appID, validHostID(value.host_id), value.services.count <= 32,
                  Set(value.services.map(\.id)).count == value.services.count else { throw TetherHostControllerError.invalidStatus }
            for service in value.services {
                try Bridge.validateScope(service.id)
            }
            services = value.services; hostID = value.host_id
            hostKey = value.host_key.flatMap { Data(base64Encoded: $0) }.flatMap { $0.count == 32 ? $0 : nil }
        }

        private func loadClients() async throws {
            let token = generation
            let data = try await ownerCommand("clients", cli: "list")
            guard generation == token else { throw CancellationError() }
            let result = try JSONDecoder().decode([TetherHostClient].self, from: data)
            guard result.count <= 256, Set(result.map(\.id)).count == result.count else {
                throw TetherHostControllerError.invalidStatus
            }
            for client in result {
                guard client.device.utf8.count == 64,
                      client.device.utf8.allSatisfy({ "0123456789abcdef".utf8.contains($0) }),
                      client.services.count <= 32,
                      client.activeSessions.map({ (0 ... 24).contains($0) }) ?? true
                else {
                    throw TetherHostControllerError.invalidStatus
                }
                for service in client.services {
                    try Bridge.validateScope(service)
                }
            }
            clients = ownerActive && transportReady ? result : result.map { TetherHostClient(device: $0.device, services: $0.services) }
        }

        private func startPresenceObservation(token: UUID) {
            presence?.cancel()
            presence = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: .seconds(2))
                        guard let self, self.generation == token, self.ownerActive else { return }
                        if self.transportReady {
                            try await self.loadClients()
                        } else {
                            self.clearPresence()
                        }
                    } catch {
                        guard !Task.isCancelled, self?.generation == token else { return }
                        self?.clearPresence()
                    }
                }
            }
        }

        private func clearPresence() {
            clients = clients.map { TetherHostClient(device: $0.device, services: $0.services) }
        }

        private func ownerCommand(_ command: String, cli: String) async throws -> Data {
            if ownerActive {
                return try await helper.request(command: command, expectedApp: appID, clientID: nil)
            }
            return try await helper.execute(scoped(cli))
        }

        private func scoped(_ command: String) -> [String] {
            ["host", command, "--config", config.path, "--expected-app", appID]
        }

        private var transportReady: Bool {
            switch state { case .listening, .relayConnected: true; default: false }
        }

        private func begin() throws {
            guard !busy else { throw TetherHostControllerError.operationInProgress }; busy = true
        }

        private func clearCode() {
            pairingGeneration = UUID()
            expiry?.cancel(); expiry = nil; pairingCode = nil; pairingExpiresAt = nil; pairingAttemptsRemaining = nil
        }

        private func validHostID(_ id: String) -> Bool {
            id.utf8.count == 52 && id.utf8.allSatisfy { (97 ... 122).contains($0) || (50 ... 55).contains($0) }
        }

        private func apply(_ event: HostEvent, route: TetherHostRoute) throws {
            switch (event.event, route) {
            case ("registered", .cloud):
                guard let id = event.id, validHostID(id), id == hostID else { throw TetherHostControllerError.invalidStatus }
                state = .relayConnected(hostID: id)
            case ("disconnected", .cloud):
                state = .relayDisconnected; clearCode(); clearPresence()
            case ("listening", .privateNetwork):
                let expected = try route.socketAddress()
                guard event.address == expected else { throw TetherHostControllerError.invalidStatus }
                state = .listening(address: expected)
            default: throw TetherHostControllerError.invalidStatus
            }
        }
    }

#endif
