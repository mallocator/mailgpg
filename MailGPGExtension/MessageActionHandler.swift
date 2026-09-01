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
        let decision = Self.colourDecision(for: message)
        log.info("decideAction: headers=\(message.headers?.count ?? -1) decision=\(decision == nil ? "none" : "colour", privacy: .public)")
        completionHandler(decision)
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
        guard let headers = message.headers else {
            log.info("colour: message has no headers")
            return nil
        }

        // Join every value of the header rather than taking the first. A
        // Content-Type is routinely folded across lines by the sending client
        // or a relay, and the protocol parameter — the part that distinguishes
        // PGP from S/MIME — is exactly what ends up on the continuation line.
        // Taking `.first` found "multipart/encrypted;" and none of the rest.
        let contentType = Self.headerValue("content-type", in: headers)
        let allHeaders = headers.values.flatMap { $0 }.joined(separator: " ").lowercased()

        log.info("colour: content-type=\(contentType.prefix(120), privacy: .public)")

        if contentType.contains("multipart/encrypted") {
            return MEMessageActionDecision.action(MEMessageAction.setBackgroundColor(.blue))
        }
        if contentType.contains("multipart/signed"),
           allHeaders.contains("application/pgp-signature") {
            // Grey, not green: nothing has verified this signature yet. Green
            // would promise a check that happens later, when the message is
            // opened and the security handler actually runs.
            return MEMessageActionDecision.action(MEMessageAction.setBackgroundColor(.gray))
        }
        return nil
    }

    /// All values of a header, joined and lowercased. MEMessage.headers maps a
    /// name to an array, and a folded header can arrive as several entries.
    private static func headerValue(_ name: String, in headers: [String: [String]]) -> String {
        guard let key = headers.keys.first(where: { $0.lowercased() == name }) else { return "" }
        return (headers[key] ?? []).joined(separator: " ").lowercased()
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
