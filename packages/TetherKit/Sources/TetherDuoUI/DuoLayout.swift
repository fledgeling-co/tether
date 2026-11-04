#if os(iOS)
import SwiftUI
import UIKit
import TetherUI

/// Optional iOS 27.1 SDK adapter. Standard TetherUI does not depend on fold APIs.
@MainActor public struct TetherDuoLayout: ViewModifier {
    @State private var divisions: [TetherDivision] = []
    public init() {}
    public func body(content: Content) -> some View {
        content.tetherLayoutDivisions(divisions)
            .background(FoldRegionReader(divisions: $divisions).allowsHitTesting(false))
    }
}

public extension View {
    @MainActor func tetherDuoLayout() -> some View { modifier(TetherDuoLayout()) }
}

private struct FoldRegionReader: UIViewRepresentable {
    @Binding var divisions: [TetherDivision]
    func makeUIView(context: Context) -> FoldObserver {
        let view = FoldObserver()
        view.onChange = { next in
            Task { @MainActor in if divisions != next { divisions = next } }
        }
        return view
    }
    func updateUIView(_ view: FoldObserver, context: Context) { view.refresh() }
}
private final class FoldObserver: UIView {
    var onChange: (([TetherDivision]) -> Void)?
    override init(frame: CGRect) {
        super.init(frame: frame); isUserInteractionEnabled = false; accessibilityElementsHidden = true
        if #available(iOS 27.1, *) {
            addInteraction(UIHingeInteraction { [weak self] _, _ in self?.refresh() })
        }
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }
    override func layoutSubviews() { super.layoutSubviews(); refresh() }
    func refresh() {
        if #available(iOS 27.1, *) {
            onChange?(reservedRegions(kind: .division, options: .includeInactive).map {
                TetherDivision(frame: $0.frame, isActive: $0.isActive)
            })
        } else { onChange?([]) }
    }
}
#endif
