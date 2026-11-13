import SwiftUI
import TetherKit

public extension TetherConnectionState {
    var displayTitle: String {
        switch self {
        case .offline: "Offline"
        case .connecting: "Connecting…"
        case .connected: "Connected"
        case .reconnecting: "Reconnecting…"
        case .revoked: "Access removed"
        case .identityMismatch: "Host identity changed"
        case .pending: "Pairing interrupted"
        }
    }
    var systemImage: String {
        switch self {
        case .connected: "checkmark.circle.fill"
        case .connecting, .reconnecting: "arrow.triangle.2.circlepath"
        case .identityMismatch: "exclamationmark.shield.fill"
        case .revoked: "person.crop.circle.badge.xmark"
        case .pending: "clock.badge.exclamationmark"
        case .offline: "network.slash"
        }
    }
}

/// A native multi-host workspace. Selecting a host leaves every other host's streams intact.
@MainActor
public struct TetherWorkspaceView: View {
    @Bindable private var store: TetherConnectionStore
    private let serviceAction: (@MainActor (String, TetherHostService) -> Void)?
    private let deviceName: String
    @State private var pairing = false
    @State private var error: String?
    @State private var removal: TetherManagedHost?
    @State private var localRemoval = false
    @State private var busy = false
    @State private var name = ""
    @State private var renaming = false
    @State private var editingRoute: TetherManagedHost?
    @State private var choosingHost = false

    /// `deviceName` is how nearby computers list this device while it pairs.
    public init(store: TetherConnectionStore, deviceName: String = TetherNearbyPairView.defaultDeviceName,
                onOpenService: (@MainActor (String, TetherHostService) -> Void)? = nil) {
        self.store = store; serviceAction = onOpenService; self.deviceName = deviceName
    }

    public var body: some View {
        TetherAdaptiveWorkspace {
            NavigationStack {
                List(store.hosts) { host in
                    Button { store.selectedHostID = host.id } label: {
                        VStack(alignment: .leading) {
                            Text(host.displayName); Text(host.state.displayTitle).font(.caption).foregroundStyle(.secondary)
                        }
                    }.listRowBackground(store.selectedHostID == host.id ? Color.accentColor.opacity(0.12) : Color.clear)
                }.navigationTitle("Hosts")
                    .toolbar { Button("Add a computer", systemImage: "plus") { pairing = true }.accessibilityIdentifier("tether.pair") }
            }
        } detail: {
            NavigationStack { selectedDetail }
        } compact: {
            nativeSplit
        }
        .sheet(isPresented: $pairing) { TetherNearbyPairView(store: store, deviceName: deviceName) }
        .sheet(isPresented: $choosingHost) {
            NavigationStack {
                List(store.hosts) { host in
                    Button {
                        store.selectedHostID = host.id; choosingHost = false
                    } label: {
                        VStack(alignment: .leading) {
                            Text(host.displayName)
                            Text(host.state.displayTitle).font(.caption).foregroundStyle(.secondary)
                        }
                    }.accessibilityIdentifier("tether.host." + host.id)
                }
                .navigationTitle("Hosts")
                .toolbar { Button("Done") { choosingHost = false } }
            }
        }
        .sheet(item: $editingRoute) { host in
            TetherRouteEditor(route: host.record.route) { route in
                try await store.changeRoute(hostID: host.id, to: route)
            }
        }
        .alert("Connection needs attention", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK", role: .cancel) { error = nil }
        } message: { Text(error ?? "") }
        .confirmationDialog(localRemoval ? "Forget this host on this device?" : "Leave this host?",
                            isPresented: Binding(get: { removal != nil }, set: { if !$0 { removal = nil } }), titleVisibility: .visible) {
            Button(localRemoval ? "Forget locally" : "Leave host", role: .destructive) {
                guard let host = removal else { return }; removal = nil
                perform {
                    if localRemoval { _ = try await store.forgetLocally(hostID: host.id) }
                    else { try await store.leave(hostID: host.id) }
                }
            }
        } message: {
            Text(localRemoval
                 ? "This deletes the saved identity here. The host keeps its permission for this device until its owner removes it."
                 : "The host will remove this device and close its active streams. Your saved identity is deleted after the host confirms removal. You will need to pair again.")
        }
        .alert("Rename host", isPresented: $renaming) {
            TextField("Name", text: $name)
            Button("Save") { if let id = store.selectedHostID { perform { try await store.renameHost(hostID: id, name: name) } } }
            Button("Cancel", role: .cancel) {}
        }
        .task { perform { try await store.load() } }
        .disabled(busy)
    }

    private var nativeSplit: some View {
        NavigationSplitView {
            hostList
                .navigationTitle("Hosts")
                .navigationSplitViewColumnWidth(min: 220, ideal: 256, max: 340)
                .toolbar { Button("Add a computer", systemImage: "plus") { pairing = true }.accessibilityIdentifier("tether.pair") }
        } detail: {
            Group {
                if let host = store.hosts.first(where: { $0.id == store.selectedHostID }) {
                    detail(host)
                } else {
                    ContentUnavailableView {
                        Label("Your hosts", systemImage: "desktopcomputer")
                    } description: {
                        Text("Add a Mac or PC to use its services here. You can keep several paired.")
                    } actions: { Button("Add a computer") { pairing = true }.buttonStyle(.borderedProminent) }
                }
            }
            #if os(iOS)
            .toolbar {
                Button("Hosts", systemImage: "sidebar.left") {
                    choosingHost = true
                }.accessibilityIdentifier("tether.show-hosts")
                Button("Add a computer", systemImage: "plus") { pairing = true }.accessibilityIdentifier("tether.pair")
            }
            #endif
        }
    }

    @ViewBuilder private var selectedDetail: some View {
        if let host = store.hosts.first(where: { $0.id == store.selectedHostID }) { detail(host) }
        else { ContentUnavailableView("Select a host", systemImage: "desktopcomputer", description: Text("Add a computer to begin.")) }
    }

    private var hostList: some View {
        List(selection: $store.selectedHostID) {
            ForEach(store.hosts) { host in
                NavigationLink(value: host.id) {
                    VStack(alignment: .leading, spacing: 4) {
                        Label(host.displayName, systemImage: "desktopcomputer")
                        Label(host.state.displayTitle, systemImage: host.state.systemImage)
                            .font(.caption).foregroundStyle(.secondary)
                    }.padding(.vertical, 4)
                }.accessibilityIdentifier("tether.host." + host.id)
            }
        }.accessibilityIdentifier("tether.hosts").overlay {
            if store.hosts.isEmpty { Text("No paired hosts").foregroundStyle(.secondary) }
        }
    }

    private func detail(_ host: TetherManagedHost) -> some View {
        Form {
            Section {
                Label(host.state.displayTitle, systemImage: host.state.systemImage)
                    .accessibilityLabel("Connection status: \(host.state.displayTitle)")
                if let checked = host.lastChecked { LabeledContent("Last checked", value: checked.formatted(date: .omitted, time: .shortened)) }
                LabeledContent("Route", value: routeName(host.record.route))
                LabeledContent("Host identity") {
                    Text(host.record.hostKey.map { String(format: "%02x", $0) }.joined())
                        .font(.caption.monospaced()).textSelection(.enabled)
                }
            } header: { Text(host.displayName) } footer: {
                Text(stateExplanation(host.state))
            }
            Section("Granted services") {
                if host.services.isEmpty { Text("Services appear after an authenticated connection.").foregroundStyle(.secondary) }
                ForEach(host.services) { service in
                    Button { serviceAction?(host.id, service) } label: {
                        LabeledContent(service.id, value: service.kind == .tcp ? "Reliable stream" : "Packet stream")
                    }.disabled(host.state != .connected || serviceAction == nil)
                }
            }
            Section {
                if host.state == .pending {
                    Button("Finish interrupted pairing") { perform { try await store.recover(hostID: host.id) } }
                    Button("Discard pending pairing", role: .destructive) { perform { try await store.discardPendingPairing(hostID: host.id) } }
                } else {
                    Button(host.state == .connected ? "Disconnect" : "Reconnect") {
                        if host.state == .connected { store.disconnect(hostID: host.id) }
                        else { store.reconnect(hostID: host.id) }
                    }.disabled(host.state == .identityMismatch || host.state == .revoked)
                    Button("Change connection…") { editingRoute = host }
                    Button("Rename host") { name = host.displayName; renaming = true }
                    Button("Leave host", role: .destructive) { localRemoval = false; removal = host }
                    Button("Forget locally…", role: .destructive) { localRemoval = true; removal = host }
                }
            }
        }
        .id(host.id)
        .formStyle(.grouped)
        .navigationTitle(host.displayName)
    }

    private func perform(_ operation: @escaping @MainActor () async throws -> Void) {
        guard !busy else { return }; busy = true
        Task { defer { busy = false }; do { try await operation() } catch { self.error = tetherErrorMessage(error) } }
    }
}

func routeName(_ route: TetherRoute) -> String {
    switch route { case .privateNetwork: "Private network / VPN"; case .cloud: "Cloud relay" }
}
func stateExplanation(_ state: TetherConnectionState) -> String {
    switch state {
    case .connected: "This host has answered an authenticated status request. Its grants control which services you can use."
    case .offline: "The host has not answered. Its saved identity is retained. Reconnect when it is available."
    case .connecting, .reconnecting: "Checking the saved host identity. Other hosts remain available."
    case .identityMismatch: "The host key differs from the saved identity. No replacement was accepted. Verify the host with its owner before pairing again."
    case .revoked: "The host no longer permits this device. Ask its owner to open a new pairing window."
    case .pending: "Pairing did not finish. Recovery checks the same saved host and device identities."
    }
}
func tetherErrorMessage(_ error: Error) -> String {
    switch error {
    case TetherClientError.identityMismatch: "The host identity changed. Verify it with the owner before pairing again."
    case TetherClientError.peerRevoked: "The host has removed this device's access."
    case TetherClientError.invalidRoute: "Check the host address, port or secure relay URL and host ID."
    case TetherClientError.pairingPending: "Finish or discard the interrupted pairing first."
    case TetherClientError.pairingExists: "This host is already paired. Select it from Hosts."
    case TetherClientError.serviceRefused: "The host has not granted this service."
    case TetherClientError.hostCapacity: "This host is handling its maximum number of streams. Close a stream or try again shortly."
    case TetherClientError.mediaUnavailable: "Native media datagrams are unavailable on this route. Choose a private network or VPN, or explicitly use a reliable packet stream in the app."
    case TetherClientError.mediaBackpressure: "The media queue is full. The app can drop a late packet or wait for capacity."
    case TetherClientError.streamLimit: "Close an active stream before opening another."
    case TetherClientError.invalidProtocol: "The invitation or host response is invalid or expired. Request a new pairing code."
    default: "The operation did not finish. Check the host and network, then try again. Saved trust has been retained."
    }
}
