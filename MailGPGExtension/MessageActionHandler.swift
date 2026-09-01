// MessageActionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "actions")

class MessageActionHandler: NSObject, MEMessageActionHandler {

    static let shared = MessageActionHandler()

    /// Mail calls this as it downloads messages. It is the only hook that sees
    /// plaintext mail — the security handler deliberately ignores anything
    /// without PGP content — which makes it the place to harvest Autocrypt
    /// keys, and the only place that can colour a row in the message list.
    func decideAction(for message: MEMessage, completionHandler: @escaping (MEMessageActionDecision?) -> Void) {
        harvestAutocryptKey(from: message)
        completionHandler(Self.colourDecision(for: message))
    }

    // MARK: - Message list colour

    /// Colour PGP mail in the message list.
    ///
    /// Returns nil for everything else rather than clearing the colour: Mail's
    /// background colour is also the user's own, set by their rules, and an
    /// extension that reset it on every message it did not care about would
    /// quietly wipe that.
    ///
    /// The decision is made from headers alone. Asking for the body would mean
    /// `invokeAgainWithBody` on every message in the mailbox, which is a large
    /// cost for the one case it adds — inline PGP, which arrives without any
    /// distinguishing header.
    private static func colourDecision(for message: MEMessage) -> MEMessageActionDecision? {
        guard GPGService.shared.getColourPGPMessages() else { return nil }
        guard let headers = message.headers,
              let contentTypeKey = headers.keys.first(where: { $0.lowercased() == "content-type" }),
              let contentType = headers[contentTypeKey]?.first?.lowercased() else { return nil }

        if contentType.contains("multipart/encrypted"),
           contentType.contains("application/pgp-encrypted") {
            return MEMessageActionDecision.action(MEMessageAction.setBackgroundColor(.blue))
        }
        if contentType.contains("multipart/signed"),
           contentType.contains("application/pgp-signature") {
            // Grey, not green: nothing has verified this signature yet. Green
            // would promise a check that happens later, when the message is
            // opened and the security handler actually runs.
            return MEMessageActionDecision.action(MEMessageAction.setBackgroundColor(.gray))
        }
        return nil
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
