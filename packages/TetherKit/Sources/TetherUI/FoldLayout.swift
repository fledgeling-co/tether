import SwiftUI

public struct TetherDivision: Equatable, Sendable {
    public var frame: CGRect
    public var isActive: Bool
    public init(frame: CGRect, isActive: Bool) { self.frame = frame; self.isActive = isActive }
}

private struct TetherDivisionsKey: EnvironmentKey {
    static let defaultValue: [TetherDivision] = []
}

public extension EnvironmentValues {
    var tetherDivisions: [TetherDivision] {
        get { self[TetherDivisionsKey.self] }
        set { self[TetherDivisionsKey.self] = newValue }
    }
}

public extension View {
    /// Supply window-local fold geometry from an optional platform adapter.
    func tetherLayoutDivisions(_ divisions: [TetherDivision]) -> some View {
        environment(\.tetherDivisions, divisions)
    }
}

/// Native adaptive layout; optional adapters supply window-local fold geometry.
@MainActor public struct TetherAdaptiveWorkspace<Primary: View, Detail: View, Compact: View>: View {
    private let primary: Primary
    private let detail: Detail
    private let compact: Compact
    @Environment(\.tetherDivisions) private var divisions
    public init(@ViewBuilder primary: () -> Primary, @ViewBuilder detail: () -> Detail,
                @ViewBuilder compact: () -> Compact) {
        self.primary = primary(); self.detail = detail(); self.compact = compact()
    }
    public var body: some View {
        #if os(iOS)
        GeometryReader { geometry in
            Group {
                if let division = divisions.first(where: {
                    let visible = $0.frame.intersection(CGRect(origin: .zero, size: geometry.size))
                    return !visible.isNull && visible.minX < geometry.size.width && visible.minY < geometry.size.height
                }), geometry.size.width >= 600 || geometry.size.height >= 800 {
                    let rect = division.frame.intersection(CGRect(origin: .zero, size: geometry.size))
                    if !division.isActive {
                        HStack(spacing: 0) {
                            primary.frame(width: min(320, geometry.size.width * 0.48))
                            detail.frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    } else if division.frame.height >= division.frame.width {
                        HStack(spacing: 0) {
                            primary.frame(width: max(0, min(division.frame.minX, geometry.size.width)))
                            Color.clear.frame(width: max(1, rect.isNull ? 0 : rect.width)).accessibilityHidden(true)
                            detail.frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    } else {
                        VStack(spacing: 0) {
                            detail.frame(height: max(0, min(division.frame.minY, geometry.size.height)))
                            Color.clear.frame(height: max(1, rect.isNull ? 0 : rect.height)).accessibilityHidden(true)
                            primary.frame(maxWidth: .infinity, maxHeight: .infinity)
                        }
                    }
                } else { compact }
            }
        }
        #else
        compact
        #endif
    }
}
