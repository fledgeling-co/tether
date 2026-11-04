#if os(iOS)
import AVFoundation
import SwiftUI
import VisionKit

/// Embedding apps provide NSCameraUsageDescription. Denial keeps manual pairing available.
@MainActor public struct TetherInvitationScanner: View {
    @Environment(\.dismiss) private var dismiss
    private let onScan: (URL) -> Void
    @State private var allowed = false
    @State private var message = "Checking camera access…"
    public init(onScan: @escaping (URL) -> Void) { self.onScan = onScan }
    public var body: some View {
        NavigationStack {
            Group {
                if allowed { InvitationCamera(onScan: onScan, onFailure: { allowed = false; message = "The camera could not start. Enter the invitation or pairing code manually." }) }
                else { ContentUnavailableView("Camera unavailable", systemImage: "camera", description: Text(message)) }
            }.navigationTitle("Scan invitation")
                .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }.task {
            guard Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription") is String else {
                message = "This app has not enabled camera access. Enter the code and host address instead."; return
            }
            guard DataScannerViewController.isSupported else {
                message = "Scanning is unavailable on this device. Enter the invitation or pairing code instead."; return
            }
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            allowed = granted && DataScannerViewController.isAvailable
            if !allowed { message = "Allow camera access in Settings, or enter the invitation and code manually." }
        }
    }
}
private struct InvitationCamera: UIViewControllerRepresentable {
    let onScan: (URL) -> Void
    let onFailure: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(onScan, onFailure) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced, recognizesMultipleItems: false, isHighFrameRateTrackingEnabled: false,
            isPinchToZoomEnabled: true, isGuidanceEnabled: true, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() } catch { Task { @MainActor in context.coordinator.onFailure() } }
        return scanner
    }
    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}
    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) { scanner.stopScanning() }
    @MainActor final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onScan: (URL) -> Void
        var completed = false
        let onFailure: () -> Void
        init(_ onScan: @escaping (URL) -> Void, _ onFailure: @escaping () -> Void) { self.onScan = onScan; self.onFailure = onFailure }
        func dataScanner(_ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            scanner.stopScanning(); onFailure()
        }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !completed else { return }
            for case let .barcode(value) in addedItems {
                if let raw = value.payloadStringValue, raw.utf8.count <= 4096,
                   let url = URL(string: raw), url.scheme == "tether", url.host == "pair" {
                    completed = true; scanner.stopScanning(); onScan(url); return
                }
            }
        }
    }
}
#endif
