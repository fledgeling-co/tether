import SwiftUI
import TetherKit
#if os(iOS)
    import UIKit
#endif

/// The six digits as two groups of three tiles, read digit by digit by VoiceOver.
public struct TetherNearbyCodeTiles: View {
    private let code: TetherNearbyCode
    @ScaledMetric(relativeTo: .largeTitle) private var size: CGFloat = 34
    public init(_ code: TetherNearbyCode) { self.code = code }
    public var body: some View {
        HStack(spacing: 6) {
            ForEach(Array(code.digits.prefix(3).enumerated()), id: \.offset) { tile($0.element) }
            Spacer().frame(width: 10)
            ForEach(Array(code.digits.suffix(3).enumerated()), id: \.offset) { tile($0.element) }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Code \(code.spoken)")
        .accessibilityIdentifier("tether.nearby.code")
    }

    private func tile(_ digit: Character) -> some View {
        Text(String(digit))
            .font(.system(size: size, weight: .semibold, design: .monospaced))
            .frame(width: size * 1.35, height: size * 1.75)
            .background(.background, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(.separator))
    }
}

/// This device and the other, joined, so each sheet names both sides of the comparison.
struct TetherNearbyIdentities: View {
    let this: String, thisSymbol: String, other: String, otherSymbol: String
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            side(this, symbol: thisSymbol)
            Rectangle().fill(.clear).frame(width: 52, height: 2)
                .overlay(Line().stroke(.tertiary, style: StrokeStyle(lineWidth: 2, dash: [2, 3]))).padding(.top, 16)
                .accessibilityHidden(true)
            side(other, symbol: otherSymbol)
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
    }

    private func side(_ name: String, symbol: String) -> some View {
        VStack(spacing: 4) {
            Image(systemName: symbol).font(.title2).accessibilityHidden(true)
            Text(name).font(.subheadline.weight(.semibold)).multilineTextAlignment(.center).lineLimit(2)
        }.frame(maxWidth: .infinity)
    }

    private struct Line: Shape {
        func path(in rect: CGRect) -> Path { Path { $0.move(to: CGPoint(x: 0, y: rect.midY)); $0.addLine(to: CGPoint(x: rect.maxX, y: rect.midY)) } }
    }
}

/// Which part of the confirmation a region shows. Tabletop puts the code on the raised half and
/// the buttons on the flat half; every other layout shows both.
public enum TetherNearbyRegion: Sendable { case all, code, controls }

/// The confirmation, waiting and result states for a nearby pairing on the requesting device.
public struct TetherNearbyConfirmView: View {
    @Bindable private var pairing: TetherNearbyPairing
    private let deviceName: String
    private let deviceSymbol: String
    private let region: TetherNearbyRegion
    private let onDone: () -> Void
    public init(pairing: TetherNearbyPairing, deviceName: String, deviceSymbol: String,
                region: TetherNearbyRegion = .all, onDone: @escaping () -> Void)
    {
        self.pairing = pairing; self.deviceName = deviceName; self.deviceSymbol = deviceSymbol
        self.region = region; self.onDone = onDone
    }

    public var body: some View {
        // The core decides the words and when Approve is enabled; the timeline keeps the
        // countdown and the one-second read delay current.
        TimelineView(.periodic(from: .now, by: 0.25)) { context in
            content(TetherCopy.nearby(pairing.state, deviceName: deviceName, canApprove: pairing.canApprove, now: context.date))
        }
        .padding(24)
        .frame(maxWidth: 460)
        .frame(maxWidth: .infinity)
    }

    private var code: TetherNearbyCode? {
        switch pairing.state {
        case let .code(code, _, _, _, _), let .waiting(code, _), let .storing(code, _): code
        default: nil
        }
    }

    private var peer: String {
        switch pairing.state {
        case let .checking(peer), let .code(_, peer, _, _, _), let .waiting(_, peer), let .storing(_, peer), let .connected(peer, _),
             let .declined(peer, _), let .expired(peer), let .failed(peer, _): peer
        case .idle: ""
        }
    }

    @ViewBuilder private func content(_ view: TetherNearbyViewModel?) -> some View {
        VStack(spacing: 16) {
            if let view {
                switch view.phase {
                case "checking":
                    if region != .controls { ProgressView(view.title) }
                case "code":
                    if region != .controls {
                        TetherNearbyIdentities(this: "This \(deviceName)", thisSymbol: deviceSymbol, other: peer, otherSymbol: "desktopcomputer")
                        Text(view.title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
                        if let code { TetherNearbyCodeTiles(code) }
                        Text(view.message).multilineTextAlignment(.center).foregroundStyle(.secondary)
                        if let note = view.note { Label(note, systemImage: "checkmark.circle").foregroundStyle(.secondary).font(.subheadline) }
                    }
                    if region != .code {
                        VStack(spacing: 12) {
                            HStack(spacing: 12) {
                                if let decline = view.secondary {
                                    Button(decline.label, role: .cancel) { pairing.decline() }
                                        .buttonStyle(.bordered).frame(maxWidth: .infinity)
                                        .accessibilityIdentifier("tether.nearby.decline")
                                }
                                if let approve = view.primary {
                                    Button(approve.label) { pairing.approve() }
                                        .buttonStyle(.borderedProminent).frame(maxWidth: .infinity)
                                        .disabled(!approve.enabled)
                                        .keyboardShortcut(.defaultAction)
                                        .accessibilityIdentifier("tether.nearby.approve")
                                }
                            }
                            .controlSize(.large)
                            if let expiry = view.expiry { Text(expiry).font(.footnote).foregroundStyle(.secondary).monospacedDigit() }
                        }
                    }
                case "waiting", "storing":
                    if region != .controls {
                        Text(view.title).font(.title2.weight(.semibold))
                        if let code { TetherNearbyCodeTiles(code) }
                        ProgressView(view.message)
                    }
                    if region != .code, let cancel = view.secondary {
                        Button(cancel.label) { pairing.cancel() }.buttonStyle(.bordered).controlSize(.large).disabled(!cancel.enabled)
                    }
                case "connected":
                    if region != .controls {
                        result("checkmark.circle.fill", tint: .green, view)
                            .task { try? await Task.sleep(for: .seconds(1.2)); onDone() }
                    }
                default:
                    if region != .controls {
                        switch view.phase {
                        case "declined": result("xmark.circle.fill", tint: .secondary, view)
                        case "expired": result("clock.badge.exclamationmark", tint: .orange, view)
                        default: result("exclamationmark.triangle.fill", tint: .orange, view)
                        }
                    }
                    if region != .code { done(view.primary?.label) }
                }
            }
        }
    }

    private func done(_ label: String?) -> some View {
        Button(label ?? "Done") { pairing.reset(); onDone() }.buttonStyle(.bordered).controlSize(.large)
    }

    private func result(_ symbol: String, tint: Color, _ view: TetherNearbyViewModel) -> some View {
        VStack(spacing: 8) {
            Image(systemName: symbol).font(.system(size: 44)).foregroundStyle(tint).accessibilityHidden(true)
            Text(view.title).font(.title2.weight(.semibold)).multilineTextAlignment(.center)
            Text(view.message).multilineTextAlignment(.center).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

/// "Add a computer": computers announcing this app on the local network, the code comparison,
/// and the typed-code route for pairing through a relay.
@MainActor public struct TetherNearbyPairView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.isPresented) private var isPresented
    @Environment(\.tetherDivisions) private var divisions
    @Bindable private var store: TetherConnectionStore
    private let deviceName: String
    private let deviceKind: String
    private let deviceSymbol: String
    private let title: String
    @State private var browser: TetherNearbyBrowser?
    @State private var pairing: TetherNearbyPairing
    @State private var listener: TetherNearbyInviteListener?
    @State private var manual = false
    @State private var settled = false

    /// `deviceName` is what computers list this device as. `title` defaults to "Add a computer";
    /// an app whose hosts are always Macs can say "Add a Mac".
    public init(store: TetherConnectionStore, deviceName: String, deviceKind: String = TetherNearbyPairView.defaultKind,
                deviceSymbol: String = TetherNearbyPairView.defaultSymbol, title: String = "Add a computer")
    {
        self.store = store; self.deviceName = deviceName; self.deviceKind = deviceKind
        self.deviceSymbol = deviceSymbol; self.title = title
        _pairing = State(initialValue: TetherNearbyPairing(store: store, deviceName: deviceName, deviceKind: deviceKind))
    }

    public static var defaultDeviceName: String {
        #if os(iOS)
            UIDevice.current.name
        #else
            Host.current().localizedName ?? "Mac"
        #endif
    }

    public static var defaultKind: String {
        #if os(iOS)
            UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone"
        #else
            "Mac"
        #endif
    }

    public static var defaultSymbol: String {
        #if os(iOS)
            UIDevice.current.userInterfaceIdiom == .pad ? "ipad" : "iphone"
        #else
            "laptopcomputer"
        #endif
    }

    private var tabletop: Bool { divisions.contains { $0.isActive && $0.frame.width > $0.frame.height } }

    public var body: some View {
        NavigationStack {
            TetherAdaptiveWorkspace {
                if tabletop, pairing.state != .idle { confirm(.controls) } else { list }
            } detail: {
                if pairing.state != .idle { confirm(tabletop ? .code : .all) }
                else {
                    Text("Choose a computer. Its code appears here.").foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } compact: {
                list.sheet(isPresented: Binding(get: { pairing.state != .idle }, set: { if !$0 { pairing.cancel() } })) {
                    confirm(.all)
                        .presentationDetents([.medium, .large])
                        .interactiveDismissDisabled(pairing.isActive)
                }
            }
            .navigationTitle(title)
            .toolbar {
                // Only when presented: as an app's first screen there is nothing to cancel back to.
                if isPresented { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { pairing.cancel(); dismiss() } } }
            }
        }
        .sheet(isPresented: $manual) { TetherPairHostView(store: store) }
        .task { start() }
        .onDisappear { stop() }
        #if os(macOS)
            .frame(minWidth: 460, idealWidth: 520, minHeight: 480)
        #endif
    }

    private func confirm(_ region: TetherNearbyRegion) -> some View {
        TetherNearbyConfirmView(pairing: pairing, deviceName: deviceKind, deviceSymbol: deviceSymbol, region: region) {
            if case .connected = pairing.state { dismiss() } else { pairing.reset() }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    @ViewBuilder private var list: some View {
        List {
            switch browser?.state {
            case .denied?:
                ContentUnavailableView {
                    Label(UICopy.text("denied_title", device: deviceKind), systemImage: "network")
                } description: {
                    Text(UICopy.text("denied_message", device: deviceKind))
                } actions: {
                    #if os(iOS)
                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                        }.buttonStyle(.borderedProminent)
                    #endif
                }
            case let .failed(message)?:
                ContentUnavailableView("Can't look for computers", systemImage: "wifi.exclamationmark", description: Text(message))
            default:
                Section {
                    if let peers = browser?.peers, !peers.isEmpty {
                        ForEach(peers) { row($0) }
                    } else if settled {
                        ContentUnavailableView(UICopy.text("empty_title"), systemImage: "wifi",
                                               description: Text(UICopy.text("empty_message")))
                    } else {
                        ForEach(0 ..< 2, id: \.self) { _ in
                            Label("Looking for computers", systemImage: "desktopcomputer").redacted(reason: .placeholder)
                        }.accessibilityHidden(true)
                    }
                } header: {
                    HStack(spacing: 6) {
                        Text(UICopy.text("section"))
                        ProgressView().controlSize(.small).accessibilityLabel("Searching")
                    }
                } footer: {
                    Text(UICopy.text("footer"))
                }
            }
            Section {
                Button(UICopy.text("manual")) { manual = true }.accessibilityIdentifier("tether.nearby.manual")
            } footer: {
                Text(UICopy.text("manual_footer"))
            }
        }
        .accessibilityIdentifier("tether.nearby.list")
    }

    private func paired(_ peer: TetherNearbyPeer) -> TetherManagedHost? {
        guard let key = peer.hostKey else { return nil }
        return store.hosts.first { $0.record.hostKey == key }
    }

    private func row(_ peer: TetherNearbyPeer) -> some View {
        let existing = paired(peer)
        return Button {
            if let existing { store.selectedHostID = existing.id; dismiss() } else { pairing.start(peer) }
        } label: {
            HStack(spacing: 12) {
                Image(systemName: peer.kind == "PC" ? "pc" : "desktopcomputer").font(.title3).frame(width: 30)
                    .foregroundStyle(.secondary).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.name).foregroundStyle(.primary)
                    Text(peer.kind).font(.subheadline).foregroundStyle(.secondary)
                }
                Spacer()
                if existing != nil { Text(UICopy.text("paired")).foregroundStyle(.secondary) }
            }
            .contentShape(Rectangle())
        }
        .tint(.primary)
        .disabled(pairing.isActive)
        .accessibilityIdentifier("tether.nearby.peer." + peer.name)
    }

    private func start() {
        guard browser == nil, let made = try? TetherNearbyBrowser(appID: store.appID) else { return }
        browser = made
        made.start()
        let pairing = pairing, appID = store.appID, name = deviceName, kind = deviceKind
        // Registering with Bonjour can block for seconds on a busy responder, so never on the main thread.
        Task.detached {
            let made = try? TetherNearbyInviteListener(appID: appID, deviceName: name, deviceKind: kind) { invite in
                Task { @MainActor in pairing.accept(invite) }
            }
            await MainActor.run { if browser != nil { listener = made } else { made?.stop() } }
        }
        Task { try? await Task.sleep(for: .seconds(2)); settled = true }
    }

    private func stop() {
        browser?.stop(); browser = nil
        listener?.stop(); listener = nil
        if pairing.isActive { pairing.cancel() }
    }
}

#if os(macOS)
    /// One nearby request on the host, with the code both screens show. Host it in a sheet or in
    /// an app's own panel; `tetherNearbyRequests` presents it as a sheet.
    @MainActor public struct TetherNearbyRequestView: View {
        @Bindable private var controller: TetherHostController
        private let request: TetherNearbyRequest
        private let invited: Bool
        private let onDecided: () -> Void
        @State private var shownAt = Date()
        @State private var error: String?
        public init(controller: TetherHostController, request: TetherNearbyRequest, invited: Bool = false, onDecided: @escaping () -> Void = {}) {
            self.controller = controller; self.request = request; self.invited = invited; self.onDecided = onDecided
        }

        public var body: some View {
            TimelineView(.periodic(from: .now, by: 0.25)) { context in
                if let view = TetherCopy.hostRequest(name: request.name, code: request.code.digits,
                                                     remainingMs: Int(request.expiresAt.timeIntervalSince(context.date) * 1000),
                                                     shownMs: Int(context.date.timeIntervalSince(shownAt) * 1000),
                                                     deviceApproved: request.deviceApproved, invited: invited,
                                                     services: controller.services.map(\.id))
                {
                    VStack(spacing: 12) {
                        Image(systemName: request.kind.contains("iPad") ? "ipad" : "iphone").font(.system(size: 34)).accessibilityHidden(true)
                        Text(view.title).font(.headline).multilineTextAlignment(.center)
                        Text(view.code.groups.joined(separator: " ")).font(.system(size: 28, weight: .semibold, design: .monospaced))
                            .accessibilityLabel("Code \(view.code.spoken)").privacySensitive()
                            .accessibilityIdentifier("tether.host.nearby.code")
                        Text(view.message).font(.callout).multilineTextAlignment(.center)
                        if let services = view.services {
                            Text(services).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                        }
                        if let note = view.note { Label(note, systemImage: "checkmark.circle").foregroundStyle(.secondary) }
                        if let error { Text(error).foregroundStyle(.red).font(.callout) }
                        HStack {
                            Button(view.secondary.label) { decide(false) }.keyboardShortcut(.cancelAction).frame(maxWidth: .infinity)
                            Button(view.primary.label) { decide(true) }.keyboardShortcut(.defaultAction).frame(maxWidth: .infinity)
                                .disabled(!view.primary.enabled)
                        }
                        .controlSize(.large)
                        Text(view.expiry).font(.footnote).foregroundStyle(.secondary).monospacedDigit()
                    }
                    .padding(20)
                    .frame(width: 340)
                }
            }
            .id(request.id)
        }

        private func decide(_ approve: Bool) {
            Task {
                do { try await controller.decideNearby(request, approve: approve); error = nil; onDecided() }
                catch { self.error = "That request has ended." }
            }
        }
    }

    @MainActor public struct TetherNearbyRequestModifier: ViewModifier {
        @Bindable var controller: TetherHostController
        let invited: Set<String>
        public func body(content: Content) -> some View {
            content.sheet(item: Binding(get: { controller.nearbyRequests.first }, set: { _ in })) { request in
                TetherNearbyRequestView(controller: controller, request: request, invited: invited.contains(request.name))
                    .interactiveDismissDisabled()
            }
        }
    }

    public extension View {
        /// Presents nearby pairing requests for this host. `invited` names devices this Mac invited.
        func tetherNearbyRequests(_ controller: TetherHostController, invited: Set<String> = []) -> some View {
            modifier(TetherNearbyRequestModifier(controller: controller, invited: invited))
        }
    }

    /// The Mac's list of nearby devices that have "Add a computer" open, each with Connect.
    @MainActor public struct TetherNearbyDevicesSection: View {
        @Bindable private var controller: TetherHostController
        private let hostName: String
        @Binding private var invited: Set<String>
        @State private var browser: TetherNearbyBrowser?
        @State private var error: String?
        public init(controller: TetherHostController, hostName: String, invited: Binding<Set<String>>) {
            self.controller = controller; self.hostName = hostName; _invited = invited
        }

        public var body: some View {
            Section {
                Toggle(UICopy.text("host_allow"), isOn: Binding(get: { controller.allowsNearby }, set: { value in
                    Task { try? await controller.setAllowsNearby(value) }
                }))
                if controller.nearbyClosedForSafety {
                    Label(UICopy.text("host_closed"),
                          systemImage: "exclamationmark.shield").foregroundStyle(.orange)
                }
                if let peers = browser?.peers, !peers.isEmpty {
                    ForEach(peers) { peer in
                        LabeledContent {
                            Button(UICopy.text("host_connect")) { connect(peer) }
                                .disabled(!controller.allowsNearby || !controller.nearbyRequests.isEmpty)
                        } label: {
                            Label { VStack(alignment: .leading) { Text(peer.name); Text(peer.kind).font(.caption).foregroundStyle(.secondary) } }
                                icon: { Image(systemName: peer.kind.contains("iPad") ? "ipad" : "iphone") }
                        }
                    }
                } else {
                    Text(UICopy.text("host_empty")).foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.red) }
            } header: {
                HStack(spacing: 6) { Text(UICopy.text("host_section")); ProgressView().controlSize(.small) }
            } footer: {
                Text(UICopy.text("host_footer"))
            }
            .task {
                guard browser == nil, let made = try? TetherNearbyBrowser(appID: controller.appID, serviceType: TetherNearbyService.device) else { return }
                browser = made; made.start()
            }
            .onDisappear { browser?.stop(); browser = nil }
        }

        private func connect(_ peer: TetherNearbyPeer) {
            invited.insert(peer.name)
            Task {
                do { try await controller.invite(peer, hostName: hostName); error = nil }
                catch { self.error = "Couldn't reach \(peer.name). Check it still has Add a computer open." }
            }
        }
    }
#endif
