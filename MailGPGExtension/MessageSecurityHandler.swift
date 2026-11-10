// MessageSecurityHandler.swift
// MailGPGExtension

import CryptoKit
import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "encode")

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {

    static let shared = MessageSecurityHandler()

    /// Two caches, deliberately keyed differently — they answer different questions.
    ///
    /// `encodeCache` is keyed by message UUID because Mail calls encode() up to
    /// three times for the same logical message (send, auto-save, Sent copy)
    /// with slightly different rawData each time; the UUID is what makes those
    /// calls recognisable as one message, and only the first should hit GPG.
    ///
    /// `decodeCache` is keyed by a hash of the message bytes, and only PGP
    /// messages ever reach it — see `decodedMessage` on why detection comes
    /// before hashing. It used to share
    /// the UUID/Message-Id key, which is wrong twice over: those headers are not
    /// unique in practice (a reply carries the original's identifiers around),
    /// and they are attacker-controlled. A collision made Mail render one
    /// message's plaintext in place of another's — silently, and permanently,
    /// because the first entry to land won. Hashing the content cannot collide
    /// across different messages, and when the bytes differ by so much as a
    /// header the worst case is a cache miss and a real decrypt.
    private var encodeCache: [String: MEMessageEncodingResult] = [:]
    private var decodeCache: [String: MEDecodedMessage] = [:]
    /// Keys of `decodeCache`, oldest first. Entries hold decrypted plaintext, so
    /// the cache is bounded on both counts: unbounded growth would keep every
    /// message you ever opened in memory, in the clear, until Mail quit.
    private var decodeCacheOrder: [String] = []
    private static let decodeCacheLimit = 24

    /// Serializes access to all three. Mail calls decodedMessage() from multiple
    /// threads concurrently — without a lock they all miss the cache and start
    /// parallel GPG decrypts of the same 17 MB message.
    private let cacheLock = NSLock()

    /// Cache key for a message's content. SHA-256 over the raw bytes: hardware
    /// accelerated, and the only identifier of a message that another message
    /// cannot borrow.
    private nonisolated static func contentKey(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private nonisolated static let inlinePGPMessageMarker = Data("-----BEGIN PGP MESSAGE-----".utf8)
    private nonisolated static let inlinePGPSignedMarker = Data("-----BEGIN PGP SIGNED MESSAGE-----".utf8)

    private func cachedEncodeResult(for key: String?) -> MEMessageEncodingResult? {
        guard let key else { return nil }
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return encodeCache[key]
    }

    private func storeEncodeResult(_ result: MEMessageEncodingResult, for key: String) {
        cacheLock.lock()
        encodeCache[key] = result
        cacheLock.unlock()
    }

    private func cachedDecodedMessage(for key: String) -> MEDecodedMessage? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return decodeCache[key]
    }

    private func storeDecodedMessage(_ decoded: MEDecodedMessage, for key: String) {
        cacheLock.lock()
        if decodeCache[key] == nil {
            decodeCacheOrder.append(key)
            while decodeCacheOrder.count > Self.decodeCacheLimit {
                decodeCache.removeValue(forKey: decodeCacheOrder.removeFirst())
            }
        }
        decodeCache[key] = decoded
        cacheLock.unlock()
    }

    func clearUUIDCache() {
        cacheLock.lock()
        encodeCache.removeAll()
        decodeCache.removeAll()
        decodeCacheOrder.removeAll()
        cacheLock.unlock()
    }

    private nonisolated static func logNSError(_ error: NSError, prefix: StaticString) {
        log.error("\(prefix, privacy: .public) domain=\(error.domain, privacy: .public) code=\(error.code)")
    }


    // MARK: - Encoding (outgoing)

    func getEncodingStatus(for message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        let policy = self.offerPolicy(for: message)

        // If we already know whether the host app is reachable, respond immediately.
        if let available = HostAppReachability.shared.isAvailable {
            completionHandler(Self.encodingStatus(hostAvailable: available, policy: policy))
            return
        }

        // Unknown state — only one caller should ping; the rest return optimistic
        // status for now (the banner in the compose panel covers the gap).
        guard HostAppReachability.shared.beginCheckIfNeeded() else {
            completionHandler(Self.encodingStatus(hostAvailable: true, policy: policy))
            return
        }

        // The fixed ping() fails fast when the host app is offline (sub-second).
        Task {
            let available: Bool
            do {
                _ = try await GPGService.shared.ping()
                available = true
            } catch {
                available = false
            }
            HostAppReachability.shared.isAvailable = available
            completionHandler(Self.encodingStatus(hostAvailable: available, policy: policy))
        }
    }

    struct OfferPolicy {
        var canSign: Bool
        var canEncrypt: Bool
    }

    /// Decide what to offer for this message.
    ///
    /// MailKit lets an extension say what it *can* do, never what Mail *will*
    /// do — `composeContext.shouldSign` and `shouldEncrypt` are read-only. Mail
    /// does however derive the compose window's initial state from this answer,
    /// so withholding an option is the only lever over "don't PGP this".
    ///
    /// The rule throughout: withhold on knowledge, never on ignorance. An
    /// earlier version returned "not offered" whenever it lacked information —
    /// before recipients were typed, before the asynchronous key lookup
    /// finished — and the result was an extension that offered nothing at all,
    /// ever. Every branch that cannot decide now offers both and says so in the
    /// log.
    private func offerPolicy(for message: MEMessage) -> OfferPolicy {
        let offerBoth = OfferPolicy(canSign: true, canEncrypt: true)

        guard GPGService.shared.getKnownCorrespondentsOnly() else {
            return offerBoth
        }

        let recipients = (message.toAddresses + message.ccAddresses + message.bccAddresses)
            .map(\.bareAddress)
            .filter { !$0.isEmpty }

        guard !recipients.isEmpty else {
            log.info("offer: no recipients yet — offering both")
            return offerBoth
        }

        guard let state = sessionState(for: message) else {
            log.info("offer: no compose state for this message — offering both")
            return offerBoth
        }

        // Recipient key lookup is asynchronous. Until every address has been
        // resolved one way or the other we do not know enough to withhold.
        let unresolved = recipients.filter {
            let status = state.recipientKeyStatus[$0]
            return status == nil || status == .loading
        }
        guard unresolved.isEmpty else {
            log.info("offer: \(unresolved.count) recipient(s) still resolving — offering both")
            return offerBoth
        }

        let known = recipients.allSatisfy { email in
            GPGService.shared.hasPGPEvidence(for: email)
                // Holding their public key already is itself a relationship: it
                // got into the keyring because you imported it or exchanged mail.
                || state.recipientKeys[email] != nil
        }
        let haveKeys = recipients.allSatisfy { state.recipientKeyStatus[$0] == .found }

        log.info("offer: recipients=\(recipients.count) known=\(known) haveKeys=\(haveKeys)")
        return OfferPolicy(canSign: known, canEncrypt: known && haveKeys)
    }

    private static func encodingStatus(hostAvailable: Bool, policy: OfferPolicy) -> MEOutgoingMessageEncodingStatus {
        guard hostAvailable else {
            return MEOutgoingMessageEncodingStatus(
                canSign: false, canEncrypt: false,
                securityError: GPGXPCError.make(.hostAppNotRunning,
                    message: "MailGPG host app is not running. Please open it to enable GPG operations."),
                addressesFailingEncryption: [])
        }
        // Don't populate addressesFailingEncryption — that causes Mail to
        // show a popup mid-composition when a recipient's key hasn't loaded yet.
        return MEOutgoingMessageEncodingStatus(
            canSign: policy.canSign, canEncrypt: policy.canEncrypt,
            securityError: nil, addressesFailingEncryption: [])
    }

    func encode(_ message: MEMessage, composeContext: MEComposeContext, completionHandler: @escaping (MEMessageEncodingResult) -> Void) {
        let shouldSign    = composeContext.shouldSign
        let shouldEncrypt = composeContext.shouldEncrypt

        log.info("encode called — shouldSign=\(shouldSign) shouldEncrypt=\(shouldEncrypt)")

        guard shouldSign || shouldEncrypt else {
            log.info("encode: no sign/encrypt requested — passing through unchanged")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        guard let body = message.rawData else {
            log.error("encode: message.rawData is nil — cannot sign/encrypt")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }

        log.info("encode: rawData size=\(body.count) bytes")

        // UUID-based cache: return a previous encode result for subsequent calls
        // with the same message UUID. This reduces 3 GPG calls to 1.
        // IMPORTANT: Skip caching for auto-saved drafts — they contain partial data
        // (X-Apple-Mail-Remote-Attachments: YES means attachments are server-side
        // references, not inlined). If we cache the draft result, the actual send
        // (which has full attachments inlined → much larger rawData) would get the
        // smaller draft result back, causing Mail to freeze.
        let messageUUID = header("x-universally-unique-identifier", in: message)
        // Auto-saved drafts have X-Apple-Mail-Remote-Attachments: YES — attachments
        // are server-side references, not inlined. Encrypting this partial message
        // wastes a large GPG call and the encrypted draft body is useless (attachment
        // refs become encrypted gibberish). Skip encoding entirely for auto-saves so
        // only the actual send (with all attachments inlined) goes through GPG.
        let isAutoSave = header("x-apple-auto-saved", in: message) != nil
                      || header("x-apple-mail-remote-attachments", in: message) != nil
        if isAutoSave {
            log.info("encode: auto-save draft detected — passing through unchanged")
            completionHandler(MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil))
            return
        }
        let cachedEncode = cachedEncodeResult(for: messageUUID)
        if let cached = cachedEncode {
            log.info("encode: UUID cache hit (\(body.count) bytes)")
            completionHandler(cached)
            return
        }

        // `rawString` is the full RFC 2822 form — "Ravi <ravi@example.com>",
        // display name and angle brackets included. Comparing that to a key's
        // bare email never matches when a display name is present. Use the
        // same normalisation the recipient lookup uses.
        let senderEmail  = message.fromAddress.bareAddress
        let state = sessionState(for: message)
        let keysByEmail = state?.recipientKeys ?? [:]

        // Split visible from blind recipients. OpenPGP stamps a key ID into the
        // packet for every recipient, and every recipient can read that list —
        // so encrypting to a BCC address the ordinary way tells the whole To
        // line who else received it. Those go in as hidden recipients instead.
        let visibleEmails = Set((message.toAddresses + message.ccAddresses).map(\.bareAddress))
        let bccEmails = Set(message.bccAddresses.map(\.bareAddress)).subtracting(visibleEmails)
        let matchedVisible = visibleEmails.compactMap { keysByEmail[$0]?.fingerprint }
        // A key carrying several UIDs can serve both a visible and a blind
        // address; keeping it visible is correct, so drop the duplicate.
        let hiddenFingerprints = bccEmails
            .compactMap { keysByEmail[$0]?.fingerprint }
            .filter { !matchedVisible.contains($0) }
        // Defensive: if address matching found nothing but we do hold keys,
        // fall back to the old behaviour rather than silently encrypting to
        // no one. Losing BCC privacy beats failing to send.
        let visibleFingerprints = (matchedVisible.isEmpty && hiddenFingerprints.isEmpty)
            ? keysByEmail.values.map(\.fingerprint)
            : matchedVisible

        // Check if encryption is requested but some recipients are missing keys.
        if shouldEncrypt {
            let allRecipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            let missingEmails = allRecipients
                .map { $0.bareAddress }
                .filter { state?.recipientKeyStatus[$0] == .notFound }
            let loadingEmails = allRecipients
                .map { $0.bareAddress }
                .filter { state?.recipientKeyStatus[$0] == .loading }

            let changedEmails = allRecipients
                .map { $0.bareAddress }
                .filter { state?.recipientKeyStatus[$0] == .keyChanged }

            if !changedEmails.isEmpty {
                let list = changedEmails.joined(separator: ", ")
                log.error("encode: refusing to encrypt — \(changedEmails.count) recipient key(s) changed")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: NSError(
                        domain: "net.pyxzl.mailgpg", code: 5,
                        userInfo: [NSLocalizedDescriptionKey:
                            "The public key for these recipients is not the one used before:\n\(list)\n\n"
                          + "This is what key substitution looks like. Confirm the new key's "
                          + "fingerprint with the recipient through another channel, then mark it "
                          + "verified in Manage Keys to accept it."])))
                return
            }

            if !missingEmails.isEmpty {
                let list = missingEmails.joined(separator: ", ")
                log.error("encode: encryption requested but \(missingEmails.count) recipient key(s) are missing")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: NSError(
                        domain: "net.pyxzl.mailgpg", code: 3,
                        userInfo: [NSLocalizedDescriptionKey:
                            "The following recipients don't have a public key:\n\(list)\n\n" +
                            "Turn off encryption to send without it, or add the missing keys."])))
                return
            }

            if !loadingEmails.isEmpty {
                let list = loadingEmails.joined(separator: ", ")
                log.warning("encode: key lookup still in progress for \(loadingEmails.count) recipient(s)")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: nil,
                    encryptionError: NSError(
                        domain: "net.pyxzl.mailgpg", code: 4,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Still looking up keys for:\n\(list)\n\nPlease try again in a moment."])))
                return
            }
        }

        Task {
            do {
                let encodedData: MEEncodedOutgoingMessage

                // Look up the sender's secret key for signing and/or encrypting
                // to the sender's own key (so the sent copy stays readable).
                log.info("encode: fetching secret keys via XPC…")
                let secretKeys = try await GPGService.shared.listSecretKeys()
                let usable = secretKeys.filter { !$0.isRevoked && $0.expiresAt.map { $0 > Date() } ?? true }
                log.info("encode: \(usable.count) usable key(s) of \(secretKeys.count) total")

                // Signing must use the key that belongs to the From address.
                // Falling back to "whatever key is first in the keyring" signs
                // outgoing mail with an unrelated identity, silently.
                //
                // Among the keys that do carry the address, prefer the one the
                // user chose in Key Management. That setting was stored and
                // displayed but never consulted when signing — a checkmark in
                // the UI that changed nothing. It is deliberately only a
                // tie-break within the matching keys: honouring it for an
                // address it does not cover would be the identity bug again,
                // wearing a preference as a disguise.
                //
                // Otherwise take the most recently created match. Several keys
                // can carry one address — an old one you stopped using beside
                // your current one — and GPG lists them in no dependable order.
                let matching = usable.filter { $0.emails.contains(senderEmail) }
                let preferredFingerprint = await GPGService.shared.getDefaultSigningKey()
                let signerKey = matching.first { $0.fingerprint == preferredFingerprint }
                    ?? matching.max { ($0.createdAt ?? .distantPast) < ($1.createdAt ?? .distantPast) }
                if signerKey == nil {
                    log.error("encode: no secret key matches the From address")
                }
                // For encryption we only need *a* key of ours so the Sent copy
                // stays decryptable — any of the user's own secret keys will do.
                let ownKeyForSentCopy = signerKey ?? usable.first

                // When encrypting, include the sender's key so the sent copy is
                // decryptable. Without this, Mail's indexer calls decodedMessage on
                // the sent message, decryption fails, and the error triggers a KVO
                // re-entrancy crash in Mail.app.
                var encryptFingerprints = visibleFingerprints
                if shouldEncrypt, let sk = ownKeyForSentCopy {
                    encryptFingerprints.append(sk.fingerprint)
                    log.info("encode: added sender key to encryption recipients")
                }

                if shouldSign {
                    guard let signerKey else {
                        log.error("encode: no usable secret key found for sender")
                        completionHandler(MEMessageEncodingResult(
                            encodedMessage: nil,
                            signingError: GPGXPCError.make(.keyNotFound, message: "No secret key found for \(senderEmail)"),
                            encryptionError: nil))
                        return
                    }
                    log.info("encode: signing with selected sender key")

                    if shouldEncrypt {
                        log.info("encode: sign+encrypt to \(encryptFingerprints.count) recipient(s), \(hiddenFingerprints.count) hidden")
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.signAndEncrypt(
                                data: body, signerKeyID: signerKey.fingerprint,
                                recipientFingerprints: encryptFingerprints,
                                hiddenRecipientFingerprints: hiddenFingerprints),
                            isSigned: true, isEncrypted: true)
                        log.info("encode: sign+encrypt succeeded")
                    } else {
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.sign(
                                data: body, signerKeyID: signerKey.fingerprint),
                            isSigned: true, isEncrypted: false)
                        log.info("encode: sign succeeded")
                    }
                } else {
                    log.info("encode: encrypt-only to \(encryptFingerprints.count) recipient(s), \(hiddenFingerprints.count) hidden")
                    encodedData = MEEncodedOutgoingMessage(
                        rawData: try await GPGService.shared.encrypt(
                            data: body, recipientFingerprints: encryptFingerprints,
                            hiddenRecipientFingerprints: hiddenFingerprints),
                        isSigned: false, isEncrypted: true)
                    log.info("encode: encrypt succeeded")
                }

                log.info("encode: encoded \(encodedData.rawData.count) bytes")

                // Evidence for next time: these addresses demonstrably accept
                // encrypted mail from us.
                if shouldEncrypt {
                    for email in visibleEmails.union(bccEmails) {
                        GPGService.shared.recordEncryptedSend(to: email)
                    }
                }

                let encodeResult = MEMessageEncodingResult(encodedMessage: encodedData, signingError: nil, encryptionError: nil)

                // Store in UUID cache: both the encode result (so subsequent
                // encode calls for the same message return instantly) and a
                // pre-built decoded message (so decodedMessage() on the encrypted
                // output also returns instantly without a GPG decrypt).
                if let uuid = messageUUID {
                    self.storeEncodeResult(encodeResult, for: uuid)
                }
                // Pre-build the decoded form so Mail's indexer does not decrypt
                // the Sent copy we just produced. Keyed by the hash of the
                // ciphertext, which is exactly the bytes Mail will hand back.
                let signer = signerKey.map {
                    Signer(email: $0.email, keyID: $0.keyID,
                           fingerprint: $0.fingerprint, trustLevel: $0.trustLevel)
                }
                let signers = signer.map { [$0] } ?? []
                let status: SecurityStatus = shouldEncrypt
                    ? .encrypted(signers: signers)
                    : .signed(signers: signers)
                if let decoded = Self.makeDecodedMessage(data: body, status: status,
                                                         wasEncrypted: shouldEncrypt) {
                    self.storeDecodedMessage(decoded, for: Self.contentKey(encodedData.rawData))
                    log.info("encode: cached decoded form under content hash")
                }

                log.info("encode: calling completionHandler with \(encodedData.rawData.count) bytes")
                completionHandler(encodeResult)

            } catch {
                let nsError = error as NSError
                Self.logNSError(nsError, prefix: "encode: failed")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: shouldSign ? nsError : nil,
                    encryptionError: shouldEncrypt ? nsError : nil))
            }
        }
    }

    // MARK: - Session lookup

    /// Finds the ComposeSessionState for an outgoing message by reading the
    /// X-MailGPG-SessionID header that ComposeSessionHandler injects.
    /// Falls back to singleActiveState so single-window use always works.
    /// Uses case-insensitive lookup because Mail normalises header capitalisation.
    private func sessionState(for message: MEMessage) -> ComposeSessionState? {
        if let idString = header("x-mailgpg-sessionid", in: message),
           let uuid = UUID(uuidString: idString) {
            return ComposeStateStore.shared.state(for: uuid)
        }
        return ComposeStateStore.shared.singleActiveState
    }

    /// Case-insensitive header lookup.
    /// Mail normalises header key capitalisation (RFC 2822 keys are case-insensitive),
    /// so direct dictionary access by the original key name is unreliable.
    private func header(_ name: String, in message: MEMessage) -> String? {
        guard let headers = message.headers else { return nil }
        guard let key = headers.keys.first(where: { $0.lowercased() == name }) else { return nil }
        return headers[key]?.first
    }

    // MARK: - Decoding (incoming)

    /// Extract a header value from raw RFC 2822 message data (case-insensitive).
    private nonisolated static func headerValue(_ name: String, in data: Data) -> String? {
        let eoh = data.range(of: Data("\r\n\r\n".utf8))
               ?? data.range(of: Data("\n\n".utf8))
        let headerData = eoh.map { Data(data[..<$0.lowerBound]) } ?? data.prefix(4096)
        // Lenient: one stray byte in the header block must not blind us to
        // every header in the message.
        // swiftlint:disable:next optional_data_string_conversion
        let headerStr = String(decoding: headerData, as: UTF8.self)
        let target = name.lowercased() + ":"
        for line in headerStr.components(separatedBy: "\n") {
            let trimmed = line.hasSuffix("\r") ? String(line.dropLast()) : line
            if trimmed.lowercased().hasPrefix(target) {
                return trimmed.dropFirst(target.count).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// Decode RFC 2047 encoded words (e.g. `=?UTF-8?Q?verschl=C3=BCsselter?=`) in a header value.
    private nonisolated static func decodeMIMEWords(_ value: String) -> String {
        let pattern = #"=\?([^?]+)\?([BbQq])\?([^?]*)\?="#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return value }
        var result = value
        for match in regex.matches(in: value, range: NSRange(value.startIndex..., in: value)).reversed() {
            guard let fullRange    = Range(match.range,        in: value),
                  let charsetRange = Range(match.range(at: 1), in: value),
                  let encRange     = Range(match.range(at: 2), in: value),
                  let textRange    = Range(match.range(at: 3), in: value) else { continue }
            let charset  = String(value[charsetRange])
            let encoding = String(value[encRange]).uppercased()
            let text     = String(value[textRange])
            let strEnc   = String.Encoding(rawValue:
                CFStringConvertEncodingToNSStringEncoding(
                    CFStringConvertIANACharSetNameToEncoding(charset as CFString)))
            var data: Data?
            if encoding == "B" {
                data = Data(base64Encoded: text, options: .ignoreUnknownCharacters)
            } else { // Q-encoding: walk bytes, _ is space, =XX is hex byte
                var bytes = [UInt8](); var i = text.startIndex
                while i < text.endIndex {
                    if text[i] == "=", let j = text.index(i, offsetBy: 3, limitedBy: text.endIndex),
                       let byte = UInt8(String(text[text.index(after: i)..<j]), radix: 16) {
                        bytes.append(byte); i = j
                    } else {
                        bytes.append(text[i] == "_" ? 0x20 : text[i].asciiValue ?? 0x3F)
                        i = text.index(after: i)
                    }
                }
                data = Data(bytes)
            }
            if let data, let decoded = String(data: data, encoding: strEnc),
               let wordRange = result.range(of: String(value[fullRange])) {
                result.replaceSubrange(wordRange, with: decoded)
            }
        }
        return result
    }

    /// Return only the RFC 2822 header block. This stays small for normal mail and
    /// avoids decoding large message bodies just to decide whether MailGPG applies.
    private nonisolated static func headerBlock(in data: Data) -> Data.SubSequence {
        let eohRange = data.range(of: Data("\r\n\r\n".utf8))
                    ?? data.range(of: Data("\n\n".utf8))
        return eohRange.map { data[..<$0.lowerBound] } ?? data.prefix(4096)
    }

    private nonisolated static func containsASCII(_ needle: Data, in data: Data) -> Bool {
        data.range(of: needle) != nil
    }

    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        // Detection runs BEFORE hashing, and that order matters. Nearly every
        // message Mail hands us is ordinary plaintext it is indexing; hashing
        // each one in full to look it up in a cache it will never be in costs
        // real CPU on a large mailbox, and a negative cache to avoid the rescan
        // would then grow one entry per message, forever. Detection is a header
        // scan plus two byte searches, so non-PGP mail leaves here having paid
        // almost nothing and having stored nothing.
        //
        // Quick pre-check: only process messages that look like PGP content.
        // Returning nil for everything else tells Mail "not my message" and avoids:
        //   - unnecessary XPC round-trips for plaintext mail
        //   - calling gpg --decrypt on multipart/signed mails we just sent, which
        //     would produce a spurious "decryption failed" banner in Sent
        // Scan the entire header block rather than a fixed byte prefix: routing
        // headers added by Gmail, Exchange, etc. (DKIM, ARC, Received, ...) can
        // push Content-Type well past 4 KB.
        let headerData = Data(Self.headerBlock(in: data))
        // Lenient: headers are ASCII by specification, and a stray byte must
        // not hide the Content-Type.
        // swiftlint:disable:next optional_data_string_conversion
        let preview = String(decoding: headerData, as: UTF8.self).lowercased()
        // For inline PGP (e.g. Mailvelope), the PGP block is in the body, not the headers.
        // Check for ASCII armor markers as bytes so normal large messages do not
        // pay the cost of converting the whole body to a Swift String.
        let isMIMEEncrypted = preview.contains("multipart/encrypted")
                           && preview.contains("application/pgp-encrypted")
        let isMIMESigned    = preview.contains("multipart/signed")
                           && preview.contains("application/pgp-signature")
        let isInlinePGP     = Self.containsASCII(Self.inlinePGPMessageMarker, in: data)
        let isInlineSigned  = Self.containsASCII(Self.inlinePGPSignedMarker, in: data)
        let isEncrypted = isMIMEEncrypted || isInlinePGP
        let isSigned    = isMIMESigned    || isInlineSigned

        log.debug("decodedMessage: \(data.count) bytes — encrypted=\(isEncrypted) signed=\(isSigned)")

        guard isEncrypted || isSigned else {
            log.debug("decodedMessage: not encrypted or signed — returning nil")
            return nil
        }

        // This message carries PGP, so its sender can handle PGP. Remember that:
        // it is the signal that decides whether we offer signing and encryption
        // when writing back to them.
        if let from = Self.headerValue("from", in: data) {
            let sender = Self.bareEmail(inHeaderValue: Self.decodeMIMEWords(from))
            if !sender.isEmpty { GPGService.shared.recordPGPReceived(from: sender) }
        }

        // Only PGP messages get hashed and cached. The key is the content
        // itself; header-derived keys collide — see the note on decodeCache.
        let cacheKey = Self.contentKey(data)
        if let cached = cachedDecodedMessage(for: cacheKey) {
            log.debug("decodedMessage: cache hit (\(data.count) bytes)")
            return cached
        }

        // MailKit requires this method to be synchronous, but our GPG calls are async.
        // We bridge with a DispatchSemaphore: a detached Task does the async work on its
        // own thread, signals when done, and the calling thread waits.
        // Using Task.detached avoids blocking a thread the cooperative executor might need.
        var result: MEDecodedMessage? = nil
        let semaphore = DispatchSemaphore(value: 0)

        if isSigned && !isEncrypted {
            // Signed-only: extract the signed data and detached signature,
            // then call gpg --verify to check the signature.
            Task.detached {
                do {
                    let (signedData, signatureData) = Self.extractSignedParts(from: data)
                    guard let signedData, let signatureData else {
                        log.error("decodedMessage: could not extract signed parts from multipart/signed")
                        semaphore.signal()
                        return
                    }
                    log.debug("decodedMessage: verifying signature (\(signedData.count) data bytes, \(signatureData.count) sig bytes)")
                    let rawStatus = try await GPGService.shared.verify(data: signedData, signature: signatureData)
                    log.debug("decodedMessage: verify completed")
                    let status = Self.checkSignerMatchesSender(rawStatus, messageData: data)
                    result = Self.makeDecodedMessage(data: data, status: status)
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: verify error")
                    switch GPGXPCError(nsError: error) {
                    case .gpgFailed:
                        result = Self.makeDecodedMessage(
                            data: data,
                            status: .signatureInvalid(reason: error.localizedDescription))
                    default:
                        result = nil
                    }
                }
                semaphore.signal()
            }
        } else {
            // Encrypted (possibly also signed): decrypt.
            Task.detached {
                do {
                    let (plaintext, rawStatus) = try await GPGService.shared.decrypt(data: data)
                    log.debug("decodedMessage: decrypt succeeded")
                    // Check against the envelope's From — that is the address
                    // Mail displays, and therefore the claim being made.
                    let status = Self.checkSignerMatchesSender(rawStatus, messageData: data)
                    // Check for protected subject (RFC 3156 / Memory Hole):
                    // if the outer subject is a placeholder like "..." and the
                    // decrypted message has a real subject, show it via banner.
                    let outerSubject = Self.headerValue("subject", in: data)
                    let innerSubject = Self.headerValue("subject", in: plaintext)
                    let banner: MEDecodedMessageBanner?
                    if let inner = innerSubject,
                       let outer = outerSubject,
                       outer == "..." && inner != outer {
                        banner = MEDecodedMessageBanner(
                            title: "🔒 Subject: \(Self.decodeMIMEWords(inner))",
                            primaryActionTitle: "",
                            dismissable: false)
                    } else {
                        banner = nil
                    }
                    result = Self.makeDecodedMessage(data: plaintext, status: status, wasEncrypted: true, banner: banner)
                } catch let error as NSError {
                    Self.logNSError(error, prefix: "decodedMessage: decrypt error")
                    // Return nil so Mail shows the raw message instead of crashing.
                    // Returning a MEDecodedMessage with the original encrypted data
                    // causes Mail's indexer to loop and trigger a KVO re-entrancy crash.
                    result = nil
                }
                semaphore.signal()
            }
        }

        semaphore.wait()

        // Cache the decoded result so subsequent calls (Mail's indexer often
        // calls decodedMessage 10+ times for the same message) return instantly.
        if let decoded = result {
            storeDecodedMessage(decoded, for: cacheKey)
            log.debug("decodedMessage: cached result")
        }

        return result
    }

    /// - Parameter wasEncrypted: `true` when returning decrypted plaintext,
    ///   so `MEMessageSecurityInformation.isEncrypted` is set correctly even
    ///   when the status isn't `.encrypted` (e.g. `.signed` after decrypt).
    /// Bare address out of a raw `From:` header value.
    /// "Ravi <ravi@example.com>" and "ravi@example.com" both yield the address.
    private nonisolated static func bareEmail(inHeaderValue value: String) -> String {
        let first = value.components(separatedBy: ",").first ?? value
        if let lt = first.firstIndex(of: "<"), let gt = first.lastIndex(of: ">"), lt < gt {
            return String(first[first.index(after: lt)..<gt])
                .trimmingCharacters(in: .whitespaces).lowercased()
        }
        return first.trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// A valid signature proves someone held a private key. It does not prove
    /// that someone is the sender. Mail renders any verified signature as a
    /// signed badge, so without this check a message claiming to come from your
    /// bank, signed by a key its author generated ten minutes ago, reads as
    /// authenticated — the signer's address is shown, but as small print beside
    /// a reassuring badge.
    ///
    /// When the signing key's address is not the one the message claims to come
    /// from, the signature is reported as invalid with both addresses named.
    /// Encryption status is unaffected: `makeDecodedMessage` still marks the
    /// message encrypted via `wasEncrypted`, so only the signature badge drops.
    nonisolated static func checkSignerMatchesSender(_ status: SecurityStatus,
                                                     messageData: Data) -> SecurityStatus {
        let signers: [Signer]
        switch status {
        case .signed(let s), .encrypted(let s): signers = s
        default: return status
        }
        guard !signers.isEmpty else { return status }

        guard let fromHeader = headerValue("from", in: messageData) else { return status }
        let from = bareEmail(inHeaderValue: decodeMIMEWords(fromHeader))
        guard !from.isEmpty else { return status }

        if signers.contains(where: { $0.email.lowercased() == from }) { return status }

        let named = signers.map(\.email).filter { !$0.isEmpty }
        let signerList = named.isEmpty ? "an unidentified key" : named.joined(separator: ", ")
        log.error("signer/sender mismatch — signature will be reported as invalid")
        return .signatureInvalid(
            reason: "Signed by \(signerList), but this message claims to be from \(from). "
                  + "The signature does not authenticate the sender.")
    }

    static nonisolated func makeDecodedMessage(data: Data, status: SecurityStatus, wasEncrypted: Bool = false, banner: MEDecodedMessageBanner? = nil) -> MEDecodedMessage? {
        let meSigners: [MEMessageSigner] = {
            switch status {
            case .signed(let signers), .encrypted(let signers):
                return signers.map {
                    MEMessageSigner(emailAddresses: [MEEmailAddress(rawString: $0.email)], signatureLabel: $0.keyID, context: nil)
                }
            default: return []
            }
        }()

        let isEncrypted: Bool = {
            if case .encrypted = status { return true }
            return wasEncrypted
        }()

        let securityInfo = MEMessageSecurityInformation(
            signers: meSigners,
            isEncrypted: isEncrypted,
            signingError: { if case .signatureInvalid(let r) = status { return NSError(domain: "MailGPG", code: 1, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }(),
            encryptionError: { if case .decryptionFailed(let r) = status { return NSError(domain: "MailGPG", code: 2, userInfo: [NSLocalizedDescriptionKey: r]) }; return nil }()
        )

        let context = try? JSONEncoder().encode(status)
        if let banner {
            return MEDecodedMessage(data: data, securityInformation: securityInfo, context: context, banner: banner)
        }
        return MEDecodedMessage(data: data, securityInformation: securityInfo, context: context)
    }

    // MARK: - Multipart/signed parser

    /// Extract the signed data (first MIME part) and detached PGP signature
    /// (second MIME part) from a multipart/signed message.
    ///
    /// RFC 3156 §5: the first part is the signed content (must be passed to
    /// gpg --verify byte-for-byte), and the second part is the detached signature.
    // MARK: - Byte-level helpers for signature extraction

    /// Split raw bytes on a byte sequence, the Data equivalent of
    /// `components(separatedBy:)`.
    private nonisolated static func split(_ data: Data, on separator: Data) -> [Data] {
        guard !separator.isEmpty else { return [data] }
        var parts: [Data] = []
        var cursor = data.startIndex
        while cursor <= data.endIndex,
              let hit = data.range(of: separator, in: cursor..<data.endIndex) {
            parts.append(Data(data[cursor..<hit.lowerBound]))
            cursor = hit.upperBound
        }
        parts.append(Data(data[cursor...]))
        return parts
    }

    /// Drop one leading and one trailing line break, CRLF or LF.
    private nonisolated static func trimmingOuterLineBreaks(_ data: Data) -> Data {
        let cr: UInt8 = 0x0D, lf: UInt8 = 0x0A
        var slice = data[...]
        if slice.first == cr, slice.dropFirst().first == lf {
            slice = slice.dropFirst(2)
        } else if slice.first == lf || slice.first == cr {
            slice = slice.dropFirst()
        }
        if slice.last == lf, slice.dropLast().last == cr {
            slice = slice.dropLast(2)
        } else if slice.last == lf || slice.last == cr {
            slice = slice.dropLast()
        }
        return Data(slice)
    }

    /// Canonical CRLF form, byte-wise.
    private nonisolated static func normalizedToCRLF(_ data: Data) -> Data {
        let cr: UInt8 = 0x0D, lf: UInt8 = 0x0A
        var out = Data()
        out.reserveCapacity(data.count + data.count / 8)
        var index = data.startIndex
        while index < data.endIndex {
            let byte = data[index]
            if byte == cr {
                let next = data.index(after: index)
                out.append(cr); out.append(lf)
                index = (next < data.endIndex && data[next] == lf) ? data.index(after: next) : next
            } else if byte == lf {
                out.append(cr); out.append(lf)
                index = data.index(after: index)
            } else {
                out.append(byte)
                index = data.index(after: index)
            }
        }
        return out
    }

    /// Pull the signed content and the detached signature out of a
    /// multipart/signed message.
    ///
    /// Works entirely in bytes. The signed content is fed to `gpg --verify`, so
    /// it has to be exactly the bytes the sender signed — and this ran through
    /// a Swift String, which meant a message whose body is not UTF-8 either
    /// bailed out with no verification at all, or, had the decode been made
    /// lenient, would have had its bytes replaced and reported a valid
    /// signature as invalid. A false alarm on a good signature is worse than
    /// no verdict.
    private nonisolated static func extractSignedParts(from data: Data) -> (signedData: Data?, signature: Data?) {
        // Only the header block is decoded as text, to find the boundary.
        // Lenient: headers are ASCII by specification.
        // swiftlint:disable:next optional_data_string_conversion
        let headerBlock = String(decoding: Self.headerBlock(in: data), as: UTF8.self)

        var boundary: String? = nil
        if let s = headerBlock.range(of: "boundary=\""),
           let e = headerBlock.range(of: "\"", range: s.upperBound..<headerBlock.endIndex) {
            boundary = String(headerBlock[s.upperBound..<e.lowerBound])
        } else if let s = headerBlock.range(of: "boundary=") {
            let rest = String(headerBlock[s.upperBound...])
            let end = rest.firstIndex(where: { ";,\r\n \t".contains($0) })
            boundary = end.map { String(rest[..<$0]) } ?? rest
        }

        guard let b = boundary, !b.isEmpty else {
            log.error("extractSignedParts: no boundary found")
            return (nil, nil)
        }

        let parts = Self.split(data, on: Data(("--" + b).utf8))
        // parts: [preamble, signed-part, signature-part, epilogue]
        guard parts.count >= 3 else {
            log.error("extractSignedParts: expected ≥3 parts, got \(parts.count)")
            return (nil, nil)
        }

        // The signed data is the COMPLETE first MIME part including its headers
        // but excluding the boundary lines and the line breaks around them.
        let signedContent = Self.trimmingOuterLineBreaks(parts[1])

        // The signature part: skip its headers, keep the armoured block.
        let sigPart = parts[2]
        guard let sepRange = sigPart.range(of: Data("\r\n\r\n".utf8))
                          ?? sigPart.range(of: Data("\n\n".utf8)) else {
            log.error("extractSignedParts: could not extract signature body")
            return (nil, nil)
        }
        // The armoured signature is ASCII; a stray byte makes gpg report the
        // signature as bad rather than skipping verification.
        // swiftlint:disable:next optional_data_string_conversion
        let sigBody = String(decoding: sigPart[sepRange.upperBound...], as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sigBody.isEmpty else {
            log.error("extractSignedParts: signature body is empty")
            return (nil, nil)
        }

        // We sign the CRLF canonical form (RFC 3156 §5); stored messages often
        // use LF, so normalise before verifying.
        let crlfSigned = Self.normalizedToCRLF(signedContent)
        log.debug("extractSignedParts: signed=\(crlfSigned.count) bytes (CRLF), sig=\(sigBody.count) chars")
        return (crlfSigned, Data(sigBody.utf8))
    }

    // MARK: - UI

    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        // Try to decode the full status from the context Data attached to each signer.
        // (We encode SecurityStatus as JSON context in makeDecodedMessage.)
        if let context = messageSigners.first?.context,
           let status = try? JSONDecoder().decode(SecurityStatus.self, from: context) {
            return SecurityDetailViewController(status: status)
        }
        // Fallback: build a .signed status from the signer labels MailKit provides.
        let signers = messageSigners.compactMap { s -> Signer? in
            guard let email = s.emailAddresses.first?.rawString else { return nil }
            return Signer(email: email, keyID: s.label, fingerprint: s.label, trustLevel: .unknown)
        }
        return SecurityDetailViewController(status: .signed(signers: signers))
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        guard let status = try? JSONDecoder().decode(SecurityStatus.self, from: context) else {
            return SecurityDetailViewController(status: .plain)
        }
        return SecurityDetailViewController(status: status)
    }

    func primaryActionClicked(forMessageContext context: Data, completionHandler: @escaping (MEExtensionViewController?) -> Void) {
        completionHandler(extensionViewController(messageContext: context))
    }
}
