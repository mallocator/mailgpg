// AutocryptHeader.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// Parsing for the `Autocrypt:` mail header (Autocrypt Level 1).
///
/// Lives in `Shared` rather than beside its only caller so it can be tested:
/// the extension's own sources are not compiled into the test target, and this
/// is pure input-parsing of attacker-supplied text — exactly the code that
/// should have tests.
public enum AutocryptHeader {

    public struct Parsed: Equatable {
        /// The address the header claims the key belongs to, lowercased.
        public let addr: String
        /// The transferable public key, decoded from base64.
        public let keyData: Data
    }

    /// Pull `addr` and `keydata` out of an `Autocrypt` header value.
    ///
    /// Attributes are semicolon-separated `name=value` pairs. Per the spec an
    /// attribute whose name begins with an underscore may be ignored, while an
    /// unrecognised attribute without that prefix means the whole header must
    /// be discarded — a receiver that ignored it could otherwise act on a
    /// header whose meaning was modified by a part it did not understand.
    ///
    /// Returns nil for anything malformed. The caller must still check that
    /// `addr` matches the message's From address before trusting the key.
    public static func parse(_ value: String) -> Parsed? {
        var addr: String?
        var keydata: String?
        var hasUnknownCriticalAttribute = false

        for rawAttribute in value.components(separatedBy: ";") {
            let attribute = rawAttribute.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !attribute.isEmpty else { continue }
            guard let separator = attribute.firstIndex(of: "=") else {
                // A bare token is not a valid attribute.
                hasUnknownCriticalAttribute = true
                continue
            }
            let name = attribute[attribute.startIndex..<separator]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let rawValue = attribute[attribute.index(after: separator)...]
                .trimmingCharacters(in: .whitespaces)

            switch name {
            case "addr":           addr = rawValue.lowercased()
            case "keydata":        keydata = rawValue
            case "prefer-encrypt": break
            default:
                if !name.hasPrefix("_") { hasUnknownCriticalAttribute = true }
            }
        }

        guard !hasUnknownCriticalAttribute else { return nil }
        guard let addr, !addr.isEmpty, let keydata else { return nil }

        // Long headers are folded, which puts CRLF and spaces through the
        // middle of the base64. Strip whitespace before decoding.
        let compact = keydata.filter { !$0.isWhitespace }
        guard !compact.isEmpty,
              let data = Data(base64Encoded: compact, options: .ignoreUnknownCharacters),
              !data.isEmpty else { return nil }

        return Parsed(addr: addr, keyData: data)
    }
}
