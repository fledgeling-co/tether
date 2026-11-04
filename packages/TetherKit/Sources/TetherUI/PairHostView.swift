import SwiftUI
import TetherKit

/// Manual pairing and QR invitation import share exactly the same scoped validation.
@MainActor public struct TetherPairHostView: View {
    @Environment(\.dismiss) private var dismiss
    private let store: TetherConnectionStore
    private let appID: String
    @State private var cloud = false
    @State private var address = ""
    @State private var port = "9000"
    @State private var relay = ""
    @State private var hostID = ""
    @State private var code = ""
    @State private var invitation = ""
    @State private var busy = false
    @State private var error: String?
    @State private var scanning = false
    public init(store: TetherConnectionStore) { self.store = store; self.appID = store.appID }
    public var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Access", selection: $cloud) {
                        Text("Private network / VPN").tag(false)
                        Text("Cloud relay").tag(true)
                    }
                    if cloud {
                        LabeledContent("Relay URL") { TextField("wss://…", text: $relay).labelsHidden() }
                        LabeledContent("Host ID") { TextField("Host ID", text: $hostID).labelsHidden() }
                    } else {
                        LabeledContent("Host address") { TextField("host.local", text: $address).labelsHidden().accessibilityIdentifier("tether.pair.address") }
                        LabeledContent("Port") { TextField("Port", text: $port).labelsHidden() }
                    }
                    LabeledContent("Pairing code") { SecureField("Pairing code", text: $code).labelsHidden().privacySensitive().accessibilityIdentifier("tether.pair.code") }
                } footer: {
                    Text(cloud ? "Use the relay URL and host ID shown by the host. The relay forwards encrypted traffic. It does not hold your application data."
                         : "Use the host's reachable address. VPN access requires both devices to be on that private network.")
                }
                Section("Pairing invitation") {
                    LabeledContent("Invitation link") { SecureField("tether://…", text: $invitation).labelsHidden().privacySensitive() }
                    Button("Use invitation") { importInvitation() }.disabled(invitation.isEmpty || busy)
                    #if os(iOS)
                    Button("Scan invitation", systemImage: "qrcode.viewfinder") { scanning = true }
                    #endif
                }
                if let error { Section { Text(error).foregroundStyle(.red).accessibilityIdentifier("tether.pair.error").accessibilityLabel("Pairing error: \(error)") } }
                Section {
                    Button { pair() } label: {
                        if busy { ProgressView("Pairing…") } else { Text("Pair host") }
                    }.disabled(busy || code.count != 8).accessibilityIdentifier("tether.pair.submit")
                } footer: { Text("Keep the host's pairing window open. Pairing establishes this app's device identity and service permissions.") }
            }
            .formStyle(.grouped).navigationTitle("Pair host")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() }.disabled(busy) } }
            .onDisappear { code = ""; invitation = "" }
            #if os(iOS)
            .sheet(isPresented: $scanning) {
                TetherInvitationScanner { url in
                    invitation = url.absoluteString; scanning = false; importInvitation()
                }
            }
            .textInputAutocapitalization(.never).autocorrectionDisabled()
            #endif
        }
        #if os(macOS)
        .frame(minWidth: 440, idealWidth: 480, minHeight: 540)
        #endif
    }
    private func importInvitation() {
        do {
            guard let url = URL(string: invitation) else { throw TetherClientError.invalidRoute }
            let value = try TetherPairingInvitation.decode(url, expectedAppID: appID)
            switch value.route {
            case let .privateNetwork(host, targetPort): cloud = false; address = host; port = String(targetPort)
            case let .cloud(url, id): cloud = true; relay = url.absoluteString; hostID = id
            }
            code = value.code; invitation = ""; error = nil
        } catch { self.error = tetherErrorMessage(error); invitation = "" }
    }
    private func pair() {
        guard !busy else { return }; busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                let route = try cloud ? TetherPairingFields.cloudRoute(relay: relay, hostID: hostID)
                    : TetherPairingFields.privateRoute(address: address, port: port)
                _ = try await store.pair(route: route, code: code.uppercased().replacingOccurrences(of: " ", with: ""))
                code = ""; dismiss()
            } catch { self.error = tetherErrorMessage(error) }
        }
    }
}
