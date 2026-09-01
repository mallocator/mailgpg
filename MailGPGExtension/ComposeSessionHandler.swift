// ComposeSessionHandler.swift
// MailGPGExtension

import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "compose")

extension MEEmailAddress {
    /// Bare email address, stripped of any RFC 2822 display name and angle brackets.
    /// e.g. "Marcel Haupt <marcel.haupt@proton.me>" → "marcel.haupt@proton.me"
    var bareAddress: String {
        let raw = rawString.trimmingCharacters(in: .whitespaces)
        if let lt = raw.firstIndex(of: "<"),
           let gt = raw.lastIndex(of: ">"), lt < gt {
            return String(raw[raw.index(after: lt)..<gt]).lowercased()
        }
        return raw.lowercased()
    }
}

class ComposeSessionHandler: NSObject, MEComposeSessionHandler {

    // MARK: - Session lifecycle

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        log.info("compose session began")
        let state = ComposeStateStore.shared.register(session)
        prepareAutocryptHeader(for: session, state: state)
    }

    /// Base64 broken into continuation lines: CRLF followed by a space, which
    /// is how RFC 5322 folds a long header value. Receivers strip the folding
    /// before decoding — our own parser drops whitespace for the same reason.
    private static func foldedBase64(_ data: Data, width: Int = 72) -> String {
        let encoded = Array(data.base64EncodedString())
        return stride(from: 0, to: encoded.count, by: width)
            .map { String(encoded[$0..<min($0 + width, encoded.count)]) }
            .joined(separator: "\r\n ")
    }

    /// True when the value can only fold its own header field and can never
    /// terminate it — the property that separates folding from injection.
    ///
    /// Two rules, and the second is the one that is easy to miss: a line break
    /// must be CRLF (a bare CR is not a fold, and parsers disagree about
    /// whether it ends a line, which is exactly the ambiguity an attacker
    /// wants), and it must be followed by a space or tab.
    static func foldsSafely(_ value: String) -> Bool {
        let scalars = Array(value.unicodeScalars)
        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            guard scalar == "\r" || scalar == "\n" else {
                index += 1
                continue
            }
            // A CR must be part of a CRLF pair; a lone LF is tolerated.
            var next = index + 1
            if scalar == "\r" {
                guard next < scalars.count, scalars[next] == "\n" else { return false }
                next += 1
            }
            guard next < scalars.count,
                  scalars[next] == " " || scalars[next] == "\t" else { return false }
            index = next + 1
        }
        return true
    }

    /// Build this session's Autocrypt header ahead of time.
    ///
    /// `additionalHeaders` has to answer synchronously and GPG lives across an
    /// XPC boundary, so the work happens when the window opens and the result
    /// waits on the session state. If it is not ready by send time the message
    /// simply goes without the header — Autocrypt is opportunistic by design.
    private func prepareAutocryptHeader(for session: MEComposeSession, state: ComposeSessionState) {
        guard GPGService.shared.getAutocryptEnabled() else { return }
        let sender = session.mailMessage.fromAddress.bareAddress
        guard !sender.isEmpty else { return }

        Task {
            do {
                let secretKeys = try await GPGService.shared.listSecretKeys()
                guard let key = secretKeys.first(where: {
                    $0.emails.contains(sender)
                        && !$0.isRevoked
                        && ($0.expiresAt.map { $0 > Date() } ?? true)
                }) else {
                    log.info("autocrypt: no usable key for the From address — no header")
                    return
                }
                let keyData = try await GPGService.shared.exportPublicKey(fingerprint: key.fingerprint)
                // prefer-encrypt=nopreference, not mutual: MailKit gives an
                // extension no way to turn encryption on by itself, so claiming
                // we encrypt by default would be a promise we cannot keep.
                //
                // The keydata must be folded. RFC 5322 caps a header line at
                // 998 octets, and base64 of a minimal key runs to 800 for
                // ed25519 and about 1250 for RSA-3072 — so an unfolded header
                // is over the hard limit for most real keys, not merely over
                // the 78-octet recommendation.
                let header = "addr=\(sender); prefer-encrypt=nopreference;\r\n"
                           + " keydata=" + Self.foldedBase64(keyData)

                // We hand Mail a value containing CRLF so the header folds
                // rather than running past RFC 5322's 998-octet line limit. The
                // difference between folding and header injection is one rule:
                // every CRLF must be followed by whitespace. Check it rather
                // than trust it — a value that could break out of its own field
                // would let anything in an address or key corrupt the message.
                guard Self.foldsSafely(header) else {
                    log.error("autocrypt: refusing to emit a header that is not safely folded")
                    return
                }
                await MainActor.run { state.autocryptHeader = header }
                log.info("autocrypt: header prepared (\(keyData.count) key bytes)")
            } catch {
                log.error("autocrypt: could not prepare header")
            }
        }
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        log.info("compose session ended")
        ComposeStateStore.shared.remove(session.sessionID)
        // Closing one compose window used to discard every cached decoded
        // message, so reading mail after writing any meant decrypting it all
        // again. Only drop the caches once no compose window is left, which is
        // the point at which the outgoing-message entries can no longer match
        // anything.
        if ComposeStateStore.shared.isEmpty {
            MessageSecurityHandler.shared.clearUUIDCache()
        }
    }

    // MARK: - Recipient annotations

    func annotateAddressesForSession(_ session: MEComposeSession) async -> [MEEmailAddress: MEAddressAnnotation] {
        guard let state = ComposeStateStore.shared.state(for: session.sessionID) else { return [:] }

        let addresses = session.mailMessage.allRecipientAddresses
        let shouldEncrypt = session.composeContext.shouldEncrypt
        var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
        var keyStatus: [String: RecipientKeyStatus] = [:]
        var recipientKeys: [String: KeyInfo] = [:]
        let localKeysByEmail: [String: KeyInfo]

        // Mark all as loading immediately so the UI shows spinners right away.
        for address in addresses {
            keyStatus[address.bareAddress] = .loading
            annotations[address] = .success(withLocalizedDescription: "Checking key…")
        }
        await MainActor.run { state.recipientKeyStatus = keyStatus }

        if shouldEncrypt {
            localKeysByEmail = [:]
        } else {
            do {
                // One entry per address, not per key: a key carrying three user
                // IDs must be findable under all three.
                localKeysByEmail = Dictionary(
                    try await GPGService.shared.listPublicKeys()
                        .filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
                        .flatMap { key in key.emails.map { ($0, key) } },
                    uniquingKeysWith: { first, _ in first }
                )
            } catch {
                for address in addresses {
                    let email = address.bareAddress
                    keyStatus[email] = .notFound
                    annotations[address] = .warning(withLocalizedDescription: "Local key lookup failed")
                }

                await MainActor.run {
                    state.recipientKeyStatus = keyStatus
                    state.recipientKeys = [:]
                }
                return annotations
            }
        }

        // Look up each recipient's public key via XPC → GPG.
        for address in addresses {
            let email = address.bareAddress
            do {
                let key = shouldEncrypt
                    ? try await GPGService.shared.lookupKey(email: email)
                    : localKeysByEmail[email]

                if let key {
                    // Trust on first use. Encryption runs with --trust-model
                    // always, so GPG will happily encrypt to whatever key turns
                    // up for an address — including one that replaced the key
                    // you used last week. Remember the fingerprint per address
                    // and refuse silently swapping it.
                    if key.viaWKD { GPGService.shared.recordWKDKey(for: email) }
                    let pinned = GPGService.shared.pinnedFingerprint(for: email)
                    if let pinned, pinned != key.fingerprint, !key.trusted {
                        keyStatus[email] = .keyChanged
                        recipientKeys[email] = key
                        annotations[address] = .error(withLocalizedDescription:
                            "Key changed (was \(String(pinned.suffix(8))), now \(key.keyID))")
                    } else {
                        // Either first contact, the same key as last time, or a
                        // key the user has verified locally — verifying is the
                        // deliberate act that accepts a replacement.
                        GPGService.shared.pin(fingerprint: key.fingerprint, for: email)
                        keyStatus[email] = .found
                        recipientKeys[email] = key
                        annotations[address] = .success(withLocalizedDescription: "Key: \(key.keyID)")
                    }
                } else {
                    keyStatus[email] = .notFound
                    let message = shouldEncrypt ? "No public key" : "No local public key"
                    annotations[address] = .warning(withLocalizedDescription: message)
                }
            } catch {
                keyStatus[email] = .notFound
                let message = shouldEncrypt ? "Key lookup failed" : "Local key lookup failed"
                annotations[address] = .warning(withLocalizedDescription: message)
            }
        }

        await MainActor.run {
            state.recipientKeyStatus = keyStatus
            state.recipientKeys = recipientKeys
        }
        return annotations
    }

    // MARK: - View controller

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        let state = ComposeStateStore.shared.state(for: session.sessionID) ?? ComposeStateStore.shared.register(session)
        return ComposeSessionViewController(state: state)
    }

    // MARK: - Headers

    func additionalHeaders(for session: MEComposeSession) -> [String: [String]] {
        // X-MailGPG-SessionID lets MessageSecurityHandler.encode() look up the
        // correct ComposeSessionState even when multiple compose windows are open.
        // MEMessageSecurityHandler only receives MEMessage + MEComposeContext, with
        // no direct reference to the originating MEComposeSession — the header is
        // the only clean bridge between the two handler types.
        var headers = ["X-MailGPG-SessionID": [session.sessionID.uuidString]]
        if let autocrypt = ComposeStateStore.shared.state(for: session.sessionID)?.autocryptHeader {
            headers["Autocrypt"] = [autocrypt]
        }
        return headers
    }

    // MARK: - Send gate

    func allowMessageSendForSession(_ session: MEComposeSession, completion: @escaping (Error?) -> Void) {
        completion(nil)
    }
}
