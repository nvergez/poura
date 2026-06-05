import Foundation

// Small hex helpers shared by the app UI and tests. Kept in the core so there's one
// definition (the macOS tool has its own private `hex`/`hexToData` in main.swift).
public extension Data {
    /// Lowercase hex, no separators: `Data([0xab,0xcd]).hexString == "abcd"`.
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    /// Lowercase hex, space-separated (matches the macOS tool's log format).
    var hexSpaced: String { map { String(format: "%02x", $0) }.joined(separator: " ") }

    /// Parse a hex string (any non-hex chars ignored) into bytes. Returns nil if the
    /// cleaned string has an odd number of hex digits.
    init?(hexString s: String) {
        let clean = s.filter { $0.isHexDigit }
        guard clean.count % 2 == 0 else { return nil }
        var d = Data(capacity: clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let b = UInt8(clean[idx..<next], radix: 16) else { return nil }
            d.append(b); idx = next
        }
        self = d
    }
}
