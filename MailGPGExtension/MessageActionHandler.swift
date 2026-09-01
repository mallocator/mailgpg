// MessageActionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "actions")

/// Runs as Mail downloads messages. Its only job is harvesting Autocrypt keys —
/// this is the sole hook that sees plaintext mail, since the security handler
/// deliberately ignores anything without PGP content.
///
/// Note the reach of this hook, because it bounds the feature: MailKit invokes
/// it only for messages delivered to the Inbox, only at download time, and
/// never retroactively. Mail that the same Mail instance sent, that a server
/// files elsewhere, or that arrived before the extension was installed is never
/// offered here. For Autocrypt that is the right scope anyway — you want keys
/// from mail people send you.
class MessageActionHandler: NSObject, MEMessageActionHandler {

    static let shared = MessageActionHandler()

    /// Headers this handler needs. MailKit supplies only what a handler asks
    /// for, so without this `message.headers` arrives empty and the Autocrypt
    /// header can never be found. It is an optional protocol requirement, which
    /// is why omitting it failed silently rather than at compile time.
    @objc var requiredHeaders: [String] {
        ["Autocrypt", "From"]
    }

    func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
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

        guard let parsed = AutocryptHeader.parse(value) else {
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
                // Advertising a key by Autocrypt is a statement that this
                // correspondent handles PGP, which is what decides whether we
                // offer signing and encryption when writing back.
                GPGService.shared.recordPGPReceived(from: parsed.addr)
                log.info("autocrypt: imported key \(imported.keyID, privacy: .public) for sender")
            } catch {
                log.error("autocrypt: import failed")
            }
        }
    }
}
