import SwiftUI
import TetherKit

/// Route changes authenticate the existing host identity before replacing a saved route.
@MainActor public struct TetherRouteEditor: View {
    @Environment(\.dismiss) private var dismiss
    private let onSave: @MainActor (TetherRoute) async throws -> Void
    @State private var cloud: Bool
    @State private var address: String
    @State private var port: String
    @State private var relay: String
    @State private var hostID: String
    @State private var busy = false
    @State private var error: String?
    public init(route: TetherRoute, onSave: @escaping @MainActor (TetherRoute) async throws -> Void) {
        self.onSave = onSave
        switch route {
        case let .privateNetwork(host, port):
            _cloud = State(initialValue: false); _address = State(initialValue: host); _port = State(initialValue: String(port))
            _relay = State(initialValue: ""); _hostID = State(initialValue: "")
        case let .cloud(url, id):
            _cloud = State(initialValue: true); _address = State(initialValue: ""); _port = State(initialValue: "9000")
            _relay = State(initialValue: url.absoluteString); _hostID = State(initialValue: id)
        }
    }
    public var body: some View {
        NavigationStack {
            Form {
                Picker("Access", selection: $cloud) {
                    Text("Private network / VPN").tag(false); Text("Cloud relay").tag(true)
                }
                if cloud {
                    LabeledContent("Relay URL") { TextField("wss://…", text: $relay).labelsHidden() }
                    LabeledContent("Host ID") { TextField("Host ID", text: $hostID).labelsHidden() }
                } else {
                    LabeledContent("Host address") { TextField("host.local", text: $address).labelsHidden() }
                    LabeledContent("Port") { TextField("Port", text: $port).labelsHidden() }
                }
                Text("The new address must prove the same saved host identity. Saving closes only this host's active streams. Other hosts remain connected.")
                    .foregroundStyle(.secondary)
                if let error { Text(error).foregroundStyle(.red) }
                Button { save() } label: { if busy { ProgressView("Checking host…") } else { Text("Verify and save") } }.disabled(busy)
            }.formStyle(.grouped).navigationTitle("Change connection")
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) } }
                #if os(iOS)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                #endif
        }
        #if os(macOS)
        .frame(minWidth: 440, minHeight: 360)
        #endif
    }
    private func save() {
        guard !busy else { return }; busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                let route = try cloud ? TetherPairingFields.cloudRoute(relay: relay, hostID: hostID)
                    : TetherPairingFields.privateRoute(address: address, port: port)
                try await onSave(route); dismiss()
            } catch { self.error = tetherErrorMessage(error) }
        }
    }
}
