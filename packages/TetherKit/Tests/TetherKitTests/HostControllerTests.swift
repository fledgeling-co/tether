#if os(macOS)
    import Foundation
    import Testing
    @testable import TetherKit

    private actor OwnerHelperFixture: HostHelper {
        let app = "app.host.tests"
        let id = String(repeating: "a", count: 52)
        var executions: [[String]] = []
        var commands: [String] = []
        var stopped = false
        var slowLaunch = false
        func delayLaunch() {
            slowLaunch = true
        }

        var foreign = false
        var windowOpen = true
        func consumeWindow() {
            windowOpen = false
        }

        var continuation: AsyncThrowingStream<HostEvent, Error>.Continuation?
        func foreignApp() {
            foreign = true
        }

        func output(_ command: String) throws -> Data {
            switch command {
            case "inspect":
                return try JSONSerialization.data(withJSONObject: ["app_id": foreign ? "app.other" : app, "host_id": id,
                                                                   "services": [["id": "api", "kind": "tcp"]]])
            case "clients", "list":
                return try JSONSerialization.data(withJSONObject: [["device": String(repeating: "b", count: 64), "services": ["api"], "active_sessions": 1, "recently_seen": true, "last_seen_unix_ms": 1234]])
            case "pairing-status":
                return try JSONSerialization.data(withJSONObject: ["open": windowOpen,
                                                                   "expires_in_seconds": windowOpen ? 299 : 0,
                                                                   "attempts_remaining": windowOpen ? 3 : 0])
            case "pair-code":
                return try JSONSerialization.data(withJSONObject: ["code": "ABCDEFGH", "expires_in_seconds": 299, "attempts_remaining": 3])
            default: return Data("{}".utf8)
            }
        }

        func execute(_ arguments: [String]) throws -> Data {
            executions.append(arguments); return try output(arguments[1])
        }

        func start(_ arguments: [String]) async throws -> AsyncThrowingStream<HostEvent, Error> {
            if slowLaunch {
                try await Task.sleep(for: .seconds(5))
            }
            executions.append(arguments)
            let (stream, continuation) = AsyncThrowingStream<HostEvent, Error>.makeStream()
            self.continuation = continuation; return stream
        }

        func request(command: String, expectedApp: String, clientID _: String?) throws -> Data {
            guard expectedApp == app else { throw TetherHostControllerError.invalidProfile }
            commands.append(command); return try output(command)
        }

        func event(_ event: String, address: String? = nil, id: String? = nil) {
            continuation?.yield(HostEvent(event: event, id: id, address: address))
        }

        func stop() -> Bool {
            stopped = true; continuation?.finish(); continuation = nil; return true
        }

        func calls() -> ([[String]], [String]) {
            (executions, commands)
        }
    }

    private actor OwnerRequestGate {
        var entered = false
        private var continuation: CheckedContinuation<Void, Never>?
        func wait() async {
            entered = true; await withCheckedContinuation { continuation = $0 }
        }

        func release() {
            continuation?.resume(); continuation = nil
        }
    }

    @MainActor @Suite("Mac host helper control")
    struct HostControllerTests {
        private func wait(_ condition: () -> Bool) async throws {
            let deadline = ContinuousClock.now.advanced(by: .seconds(5))
            while !condition() {
                guard ContinuousClock.now < deadline else { throw TetherClientError.timeout }
                try await Task.sleep(for: .milliseconds(10))
            }
        }

        @Test func legacyClientListHasUnknownPresence() throws {
            let data = Data(("[{\"device\":\"" + String(repeating: "b", count: 64) + "\",\"services\":[\"api\"]}]").utf8)
            let clients = try JSONDecoder().decode([TetherHostClient].self, from: data)
            #expect(clients.first?.activeSessions == nil && clients.first?.recentlySeen == nil)
        }

        @Test func fixedProfilesAndRoutesRefuseUnboundedDestinations() throws {
            #expect(throws: (any Error).self) {
                try TetherHostServiceProfile(id: "api", kind: .tcp, loopbackAddress: "example.com", port: 443)
            }
            #expect(throws: (any Error).self) { try TetherHostRoute.privateNetwork(address: "host.example", port: 7445).arguments() }
            #expect(throws: (any Error).self) {
                try TetherHostRoute.cloud(relayURL: #require(URL(string: "wss://user:secret@relay.example"))).arguments()
            }
            let profile = try TetherHostServiceProfile(id: "api", kind: .tcp, loopbackAddress: "::1", port: 8882)
            #expect(profile.argument == "api=tcp://[::1]:8882")
            #expect(try TetherHostRoute.privateNetwork(address: "0:0:0:0:0:0:0:1", port: 7445).arguments() == ["--direct", "[::1]:7445"])
        }

        @Test func readinessIsObservedAndOwnerCommandsStayScoped() async throws {
            let helper = OwnerHelperFixture()
            let controller = try TetherHostController(helper: helper, configurationURL: URL(fileURLWithPath: "/tmp/synthetic-host.json"),
                                                      appID: "app.host.tests")
            try await controller.initialize(services: [TetherHostServiceProfile(id: "api", kind: .tcp, port: 8882)])
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
            #expect(controller.state == .starting)
            #expect(controller.pairingCode == nil)
            await helper.event("listening", address: "127.0.0.1:7445")
            try await wait { controller.state == .listening(address: "127.0.0.1:7445") }
            try await controller.openPairingWindow()
            #expect(controller.pairingCode == "ABCDEFGH")
            #expect(controller.pairingAttemptsRemaining == 3)
            try await controller.refreshClients()
            #expect(controller.clients.count == 1)
            #expect(controller.clients.first?.activeSessions == 1)
            try await controller.revoke(clientID: String(repeating: "b", count: 64))
            let calls = await helper.calls()
            #expect(calls.1.contains("inspect") && calls.1.contains("pair-code") && calls.1.contains("clients") && calls.1.contains("revoke"))
            let run = try #require(calls.0.first { $0.contains("run") })
            #expect(run.contains("--managed-stdin") && run.contains("--status-json"))
            #expect(!run.contains("--pair"))
            await controller.stop()
            #expect(controller.state == .stopped && controller.pairingCode == nil)
            #expect(controller.clients.allSatisfy { $0.activeSessions == nil && $0.recentlySeen == nil })
            #expect(await helper.stopped)
        }

        @Test func consumedPairingWindowClearsTheDisplayedCode() async throws {
            let helper = OwnerHelperFixture()
            let controller = try TetherHostController(helper: helper, configurationURL: URL(fileURLWithPath: "/tmp/synthetic-host.json"),
                                                      appID: "app.host.tests")
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
            await helper.event("listening", address: "127.0.0.1:7445")
            try await wait { controller.state == .listening(address: "127.0.0.1:7445") }
            try await controller.openPairingWindow()
            await helper.consumeWindow()
            try await wait { controller.pairingCode == nil }
            #expect(controller.pairingExpiresAt == nil && controller.pairingAttemptsRemaining == nil)
            await controller.stop()
        }

        @Test func stopCancelsAnInFlightLaunchWithoutRestoringOnlineState() async throws {
            let helper = OwnerHelperFixture(); await helper.delayLaunch()
            let controller = try TetherHostController(helper: helper, configurationURL: URL(fileURLWithPath: "/tmp/synthetic-host.json"),
                                                      appID: "app.host.tests")
            let launching = Task { try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445)) }
            try await wait { controller.state == .starting }
            await controller.stop()
            do { try await launching.value; Issue.record("cancelled launch completed") } catch is CancellationError {}
            #expect(controller.state == .stopped)
            #expect(await helper.stopped)
        }

        @Test func realOwnedProcessUsesCorrelatedPipeAndStopsOnEOF() async throws {
            let stage = FileManager.default.temporaryDirectory.appendingPathComponent("tether-helper-test-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: stage) }
            let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Fixtures/managed_host.py")
            let config = stage.appendingPathComponent("synthetic.json")
            let controller = try TetherHostController(helperURL: script, configurationURL: config, appID: "app.host.tests")
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
            try await wait { controller.state == .listening(address: "127.0.0.1:7445") }
            try await controller.openPairingWindow()
            #expect(controller.pairingCode == "ABCDEFGH")
            try await controller.refreshClients()
            #expect(controller.clients.isEmpty)
            await controller.stop()
            try await wait { FileManager.default.fileExists(atPath: config.deletingPathExtension().appendingPathExtension("closed").path) }
            #expect(controller.state == .stopped)
        }

        @Test func relayDisconnectClearsCodeAndPresenceAndRefusesNewWindow() async throws {
            let helper = OwnerHelperFixture()
            let controller = try TetherHostController(helper: helper, configurationURL: URL(fileURLWithPath: "/tmp/synthetic-host.json"),
                                                      appID: "app.host.tests")
            try await controller.start(route: .cloud(relayURL: #require(URL(string: "wss://relay.example/tether"))))
            await helper.event("registered", id: String(repeating: "a", count: 52))
            try await wait { controller.state == .relayConnected(hostID: String(repeating: "a", count: 52)) }
            try await controller.openPairingWindow(); try await controller.refreshClients()
            await helper.event("disconnected")
            try await wait { controller.state == .relayDisconnected }
            #expect(controller.pairingCode == nil)
            #expect(controller.clients.allSatisfy { $0.activeSessions == nil && $0.recentlySeen == nil })
            do { try await controller.openPairingWindow(); Issue.record("disconnected relay opened a new pairing window") }
            catch TetherHostControllerError.helperFailed {}
            await controller.stop()
        }

        @Test func stalledOwnedHelperExitsBeforeReplacementStarts() async throws {
            let stage = FileManager.default.temporaryDirectory.appendingPathComponent("tether-stalled-helper-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: stage) }
            let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Fixtures/managed_host.py")
            let config = stage.appendingPathComponent("stalled.json")
            let controller = try TetherHostController(helperURL: script, configurationURL: config, appID: "app.host.tests")
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
            try await wait { controller.state == .listening(address: "127.0.0.1:7445")
                && FileManager.default.fileExists(atPath: config.deletingPathExtension().appendingPathExtension("pid").path)
            }
            let request = Task { try await controller.refreshClients() }
            try await Task.sleep(for: .milliseconds(20))
            let started = ContinuousClock.now
            await controller.stop()
            #expect(started.duration(to: .now) < .seconds(6))
            #expect(controller.state == .stopped)
            do { try await request.value; Issue.record("stalled request completed") } catch {}
            try Data().write(to: config.deletingPathExtension().appendingPathExtension("graceful"))
            try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
            try await wait { controller.state == .listening(address: "127.0.0.1:7445") }
            await controller.stop()
            #expect(controller.state == .stopped)
        }

        @Test func preCancelledOwnerRequestNeverEntersThePipe() async throws {
            let stage = FileManager.default.temporaryDirectory.appendingPathComponent("tether-cancel-helper-" + UUID().uuidString)
            try FileManager.default.createDirectory(at: stage, withIntermediateDirectories: false)
            defer { try? FileManager.default.removeItem(at: stage) }
            let script = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Fixtures/managed_host.py")
            let config = stage.appendingPathComponent("synthetic.json")
            let helper = ProcessHostHelper(executable: script)
            let events = try await helper.start(["host", "run", "--config", config.path, "--expected-app", "app.host.tests",
                                                 "--direct", "127.0.0.1:7445", "--managed-stdin", "--status-json"])
            let drain = Task { do { for try await _ in events {} } catch {} }
            let gate = OwnerRequestGate()
            let request = Task { await gate.wait(); return try await helper.request(command: "clients", expectedApp: "app.host.tests", clientID: nil) }
            while !(await gate.entered) {
                await Task.yield()
            }
            request.cancel(); await gate.release()
            do { _ = try await request.value; Issue.record("pre-cancelled owner request completed") } catch is CancellationError {}
            #expect(!FileManager.default.fileExists(atPath: config.deletingPathExtension().appendingPathExtension("requests").path))
            #expect(await helper.stop())
            drain.cancel()
        }

        @Test func wrongAppAndWrongRelayIdentityCannotBecomeOnline() async throws {
            let helper = OwnerHelperFixture()
            let controller = try TetherHostController(helper: helper, configurationURL: URL(fileURLWithPath: "/tmp/synthetic-host.json"),
                                                      appID: "app.host.tests")
            try await controller.start(route: .cloud(relayURL: #require(URL(string: "wss://relay.example/tether"))))
            #expect(controller.state == .starting)
            await helper.event("registered", id: String(repeating: "b", count: 52))
            try await wait { controller.state == .failed }
            #expect(await helper.stopped)
            await helper.foreignApp()
            do {
                try await controller.start(route: .privateNetwork(address: "127.0.0.1", port: 7445))
                Issue.record("foreign app configuration started")
            } catch TetherHostControllerError.invalidStatus {}
        }
    }
#endif
