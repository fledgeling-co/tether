import SwiftUI
import TetherKit
import TetherUI
#if os(iOS) && TETHER_DUO_UI
import TetherDuoUI
#endif

@main struct WorkspaceApp: App {
    @State private var model = WorkspaceModel()
    var body: some Scene {
        WindowGroup("Tether Workspace") {
            Group {
                if let store = model.store {
                    VStack(spacing: 0) {
                        #if os(macOS)
                        Picker("Role", selection: $model.hosting) {
                            Text("Your hosts").tag(false); Text("Host this Mac").tag(true)
                        }.pickerStyle(.segmented).padding().frame(maxWidth: 400)
                        if model.hosting {
                            if let host = model.host {
                                TetherHostSettingsView(controller: host, initialServices: model.profiles)
                            } else {
                                ContentUnavailableView("Host helper required", systemImage: "desktopcomputer",
                                    description: Text("Bundle the built tether helper at Contents/Helpers/tether to enable hosting in this example."))
                            }
                        } else { TetherWorkspaceView(store: store) }
                        #else
                        TetherWorkspaceView(store: store)
                        #endif
                        if model.fixtures { Text("Design fixtures · No network connection").font(.caption).foregroundStyle(.secondary).padding(6) }
                    }
                } else {
                    ContentUnavailableView("Workspace unavailable", systemImage: "exclamationmark.triangle",
                        description: Text("The app could not initialize its scoped transport configuration."))
                }
            }
            #if os(iOS) && TETHER_DUO_UI
            .tetherDuoLayout()
            #endif
            #if os(macOS)
            .frame(minWidth: 780, minHeight: 580)
            #endif
        }
    }
}
@MainActor @Observable final class WorkspaceModel {
    let fixtures = ProcessInfo.processInfo.arguments.contains("--design-fixtures")
    var store: TetherConnectionStore?
    var hosting = false
    #if os(macOS)
    var host: TetherHostController?
    var profiles: [TetherHostServiceProfile] = []
    #endif
    init() {
        let scope = "app.fledgeling.tether.workspace"
        do {
            let client: any TetherClientManaging
            if fixtures { client = DesignClient(appID: scope) }
            else { client = try TetherClient(appID: scope) }
            store = try TetherConnectionStore(client: client)
            #if os(macOS)
            if !fixtures, let helper = Bundle.main.executableURL?.deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Helpers/tether"), FileManager.default.isExecutableFile(atPath: helper.path) {
                let folder = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                    appropriateFor: nil, create: true).appendingPathComponent("TetherWorkspace", isDirectory: true)
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                host = try TetherHostController(helperURL: helper, configurationURL: folder.appendingPathComponent("host.json"), appID: scope)
                profiles = [try TetherHostServiceProfile(id: "example-api", kind: .tcp, port: 9123)]
            }
            #endif
        } catch { store = nil }
    }
}

/// Explicit launch-only design data. Production uses TetherClient and this app's device-only Keychain.
private actor DesignClient: TetherClientManaging {
    nonisolated let appID: String
    init(appID: String) { self.appID = appID }
    func records() throws -> [TetherPeerRecord] {
        try (1...3).map { index in
            let json: [String: Any] = ["appID": appID, "hostKey": Data(repeating: UInt8(index), count: 32).base64EncodedString(),
                "clientKey": Data(repeating: 7, count: 32).base64EncodedString(), "confirmed": true,
                "pairingID": UUID().uuidString, "route": ["privateNetwork": ["host": "host-\(index).local", "port": 9000]]]
            return try JSONDecoder().decode(TetherPeerRecord.self, from: JSONSerialization.data(withJSONObject: json))
        }
    }
    func status(_ record: TetherPeerRecord) throws -> TetherHostStatus {
        throw TetherClientError.connectionClosed
    }
    func pair(route: TetherRoute, code: String) throws -> TetherPeerRecord { throw TetherClientError.connectionClosed }
    func recover(_ record: TetherPeerRecord) throws -> TetherPeerRecord { throw TetherClientError.connectionClosed }
    func leave(_ record: TetherPeerRecord) throws { throw TetherClientError.connectionClosed }
    func forgetLocally(_ record: TetherPeerRecord) throws -> TetherLocalForgetResult { throw TetherClientError.connectionClosed }
    func discardPendingPairing(_ record: TetherPeerRecord) throws { throw TetherClientError.connectionClosed }
    func openService(_ name: String, kind: TetherServiceKind, peer: TetherPeerRecord) throws -> TetherServiceStream { throw TetherClientError.connectionClosed }
}
