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
                    $0.email.lowercased() == sender
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
                let header = "addr=\(sender); prefer-encrypt=nopreference; "
                           + "keydata=\(keyData.base64EncodedString())"
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
        MessageSecurityHandler.shared.clearUUIDCache()
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
                localKeysByEmail = Dictionary(
                    try await GPGService.shared.listPublicKeys()
                        .filter { !$0.isRevoked && ($0.expiresAt.map { $0 > Date() } ?? true) }
                        .map { ($0.email.lowercased(), $0) },
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
