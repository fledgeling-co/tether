#if os(macOS)
import CoreImage.CIFilterBuiltins
import SwiftUI
import TetherKit

/// Native owner controls for the helper bundled with the embedding Mac app.
@MainActor public struct TetherHostSettingsView: View {
    @Bindable private var controller: TetherHostController
    private let initialServices: [TetherHostServiceProfile]
    @State private var cloud = false
    @State private var bindAddress = "127.0.0.1"
    @State private var port = "9000"
    @State private var relay = ""
    @State private var advertisedAddress = ""
    @State private var busy = false
    @State private var error: String?
    @State private var removing: TetherHostClient?
    @State private var stopping = false
    @State private var presenceChecked: Date?
    public init(controller: TetherHostController, initialServices: [TetherHostServiceProfile]) {
        self.controller = controller; self.initialServices = initialServices
    }
    public var body: some View {
        Form {
            Section {
                LabeledContent("Status", value: status)
                Picker("Access", selection: $cloud) {
                    Text("Private network / VPN").tag(false)
                    Text("Cloud relay").tag(true)
                }.disabled(running)
                if cloud { TextField("Secure relay URL", text: $relay).disabled(running) }
                else {
                    TextField("Listen address", text: $bindAddress).disabled(running)
                    TextField("Port", text: $port).disabled(running)
                    TextField("Address clients can reach", text: $advertisedAddress)
                }
                if running { Button("Stop hosting", role: .destructive) { stopping = true } }
                else {
                    Button("Create host configuration") { perform { try await controller.initialize(services: initialServices) } }
                        .disabled(initialServices.isEmpty || controller.hostID != nil)
                    Button("Start hosting") { start() }
                }
            } header: { Text("Host access") } footer: {
                Text("Private access uses your network or VPN. Cloud access requires an authorized relay registration. Changing access stops the current host first.")
            }
            Section("Pair a device") {
                Button("Open pairing window") { perform { try await controller.openPairingWindow() } }.disabled(!running)
                if let code = controller.pairingCode, let expiry = controller.pairingExpiresAt {
                    Text(code).font(.largeTitle.monospaced().weight(.semibold)).privacySensitive()
                        .accessibilityLabel("Pairing code \(code.map(String.init).joined(separator: " "))")
                    Button("Copy pairing code") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(code, forType: .string)
                    }
                    TimelineView(.periodic(from: .now, by: 1)) { _ in
                        Text("Expires \(expiry, style: .relative) · \(controller.pairingAttemptsRemaining ?? 0) attempts remaining")
                    }
                    if let url = invitation(code: code, expiry: expiry), let image = qr(url) {
                        Image(nsImage: image).interpolation(.none).resizable().scaledToFit().frame(width: 160, height: 160)
                            .privacySensitive().accessibilityLabel("Pairing invitation QR code")
                    } else if !cloud {
                        Text("Enter a reachable client address above to show a QR invitation.").foregroundStyle(.secondary)
                    }
                    Text("Share only with the person pairing. The code expires after one successful pairing.").foregroundStyle(.secondary)
                }
            }
            Section("Paired clients") {
                Button("Refresh clients", systemImage: "arrow.clockwise") { perform { try await controller.refreshClients(); presenceChecked = .now } }
                if let checked = presenceChecked { Text("Presence checked \(checked, style: .time)").font(.caption).foregroundStyle(.secondary) }
                if controller.clients.isEmpty { Text("No paired clients").foregroundStyle(.secondary) }
                ForEach(controller.clients) { client in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(client.device).font(.caption.monospaced()).textSelection(.enabled)
                        Text(client.services.joined(separator: ", ")).foregroundStyle(.secondary)
                        Label(presence(client), systemImage: (client.activeSessions ?? 0) > 0 && running ? "checkmark.circle.fill" : "network.slash").font(.caption).foregroundStyle(.secondary)
                        Button("Remove client", role: .destructive) { removing = client }
                    }
                }
            }
            Section("Host services") {
                ForEach(controller.services) { service in LabeledContent(service.id, value: service.kind.rawValue.uppercased()) }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }.formStyle(.grouped).disabled(busy)
        .task {
            do { try await controller.refreshClients(); presenceChecked = .now } catch {}
        }
        .onChange(of: controller.clients) { _, _ in presenceChecked = .now }
        .confirmationDialog("Remove this client?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Remove client", role: .destructive) {
                if let client = removing { removing = nil; perform { try await controller.revoke(clientID: client.id) } }
            }
        } message: { Text("This closes the client's active streams and removes its permissions. It must pair again to regain access.") }
        .confirmationDialog("Stop hosting?", isPresented: $stopping, titleVisibility: .visible) {
            Button("Stop hosting", role: .destructive) { Task { await controller.stop() } }
        } message: { Text("Active client connections will close. Paired device permissions are retained.") }
    }
    private func presence(_ client: TetherHostClient) -> String {
        guard running else { return "Presence unavailable while host is stopped" }
        if let sessions = client.activeSessions, sessions > 0 { return "Active · \(sessions) connections" }
        if client.recentlySeen == true { return "Seen recently" }
        if client.activeSessions != nil { return "Not connected" }
        return "Presence unavailable"
    }
    private var running: Bool {
        switch controller.state { case .stopped, .failed: false; default: true }
    }
    private var status: String {
        switch controller.state {
        case .stopped: "Stopped"
        case .starting: "Starting…"
        case let .listening(address): "Listening on \(address)"
        case .relayConnected: "Connected to relay"
        case .relayDisconnected: "Relay offline"
        case .failed: "Host stopped unexpectedly"
        }
    }
    private func start() {
        perform {
            let route: TetherHostRoute
            if cloud {
                guard let url = URL(string: relay) else { throw TetherClientError.invalidRoute }
                route = .cloud(relayURL: url)
            } else {
                guard let p = UInt16(port), p > 0 else { throw TetherClientError.invalidRoute }
                route = .privateNetwork(address: bindAddress, port: p)
            }
            try await controller.start(route: route)
        }
    }
    private func invitation(code: String, expiry: Date) -> URL? {
        let route: TetherRoute
        if cloud {
            guard let url = URL(string: relay), let id = controller.hostID else { return nil }
            route = .cloud(relayURL: url, hostID: id)
        } else {
            guard let r = try? TetherPairingFields.privateRoute(address: advertisedAddress, port: port) else { return nil }
            route = r
        }
        return try? TetherPairingInvitation(appID: controller.appID, route: route, code: code, expiresAt: expiry).url()
    }
    private func qr(_ url: URL) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator(); filter.message = Data(url.absoluteString.utf8)
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 5, y: 5)),
              let image = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return NSImage(cgImage: image, size: NSSize(width: output.extent.width, height: output.extent.height))
    }
    private func perform(_ operation: @escaping @MainActor () async throws -> Void) {
        guard !busy else { return }; busy = true; error = nil
        Task { defer { busy = false }; do { try await operation() } catch { self.error = tetherErrorMessage(error) } }
    }
}
#endif
