// MessageActionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "autocrypt")

class MessageActionHandler: NSObject, MEMessageActionHandler {

    static let shared = MessageActionHandler()

    func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
        // Harvest the sender's key from an Autocrypt header, if there is one.
        // Mail calls this as messages are downloaded, which is the only hook
        // that sees plaintext mail — the security handler deliberately ignores
        // anything without PGP content, and Autocrypt headers ride on ordinary
        // messages.
        harvestAutocryptKey(from: message)

        // No action on the message itself.
        completionHandler(nil)
    }

    // MARK: - Autocrypt

    private func harvestAutocryptKey(from message: MEMessage) {
        guard GPGService.shared.getAutocryptEnabled() else { return }
        guard let headers = message.headers,
              let key = headers.keys.first(where: { $0.lowercased() == "autocrypt" }),
              let value = headers[key]?.first else { return }

        guard let parsed = Self.parseAutocryptHeader(value) else {
            log.info("autocrypt: header present but unusable")
            return
        }

        // The spec requires addr to match the From address. Without this check
        // any sender could publish a key for any address and have it imported.
        let from = message.fromAddress.bareAddress
        guard !from.isEmpty, parsed.addr == from else {
            log.error("autocrypt: addr does not match From — ignoring header")
            return
        }

        Task {
            do {
                let imported = try await GPGService.shared.importKeyData(parsed.keyData)
                log.info("autocrypt: imported key \(imported.keyID, privacy: .public) for sender")
            } catch {
                log.error("autocrypt: import failed")
            }
        }
    }

    /// Pull `addr` and `keydata` out of an Autocrypt header value.
    ///
    /// Attributes are semicolon-separated `name=value` pairs. Any attribute
    /// whose name starts with an underscore is by spec ignorable; an unknown
    /// attribute without that prefix means the header must be dropped
    /// entirely, which is what the `criticalUnknown` check enforces.
    static func parseAutocryptHeader(_ value: String) -> (addr: String, keyData: Data)? {
        var addr: String?
        var keydata: String?
        var criticalUnknown = false

        for rawAttr in value.components(separatedBy: ";") {
            let attr = rawAttr.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !attr.isEmpty else { continue }
            guard let eq = attr.firstIndex(of: "=") else { continue }
            let name = String(attr[attr.startIndex..<eq]).trimmingCharacters(in: .whitespaces).lowercased()
            let val  = String(attr[attr.index(after: eq)...]).trimmingCharacters(in: .whitespaces)

            switch name {
            case "addr":           addr = val.lowercased()
            case "keydata":        keydata = val
            case "prefer-encrypt": break
            default:
                if !name.hasPrefix("_") { criticalUnknown = true }
            }
        }

        guard !criticalUnknown else { return nil }
        guard let addr, !addr.isEmpty, let keydata else { return nil }

        // Folding puts whitespace through the base64; strip it before decoding.
        let compact = keydata.filter { !$0.isWhitespace }
        guard let data = Data(base64Encoded: compact, options: .ignoreUnknownCharacters),
              !data.isEmpty else { return nil }
        return (addr, data)
    }
}
