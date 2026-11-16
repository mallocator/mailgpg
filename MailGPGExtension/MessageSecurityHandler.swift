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
    /// `encodeCache` is keyed by message UUID plus everything that decides the
    /// output (`OutgoingMessage.cacheKey`), because Mail calls encode() up to
    /// three times for the same logical message, and an edited message must not
    /// get the old ciphertext back. Auto-saves skip GPG (see `encode`). A Send
    /// still runs GPG twice: Mail's first call carries an empty text/plain part
    /// and its second, the one that goes out, the full text, so the two cannot
    /// share a result (MGP-26).
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
    /// Mail calls decodedMessage() from multiple threads concurrently; the
    /// cache also tracks the decodes still running, so those calls share one
    /// GPG decrypt of the same 17 MB message instead of starting one each.
    /// A caller waits at most 60 s, room for a passphrase prompt; `DecodeCache`
    /// explains that bound and the 24-entry one.
    private let decodeCache = DecodeCache<MEDecodedMessage>(limit: 24, timeout: 60)

    /// Serializes access to `encodeCache`.
    private let cacheLock = NSLock()

    /// Cache key for a message's content. SHA-256 over the raw bytes: hardware
    /// accelerated, and the only identifier of a message that another message
    /// cannot borrow.
    private nonisolated static func contentKey(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

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

    func clearUUIDCache() {
        cacheLock.lock()
        encodeCache.removeAll()
        cacheLock.unlock()
        decodeCache.removeAll()
    }

    /// Decode messages afresh, e.g. once a missing signer key was fetched.
    func clearDecodeCache() {
        decodeCache.removeAll()
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
            let available: Bool?
            do {
                _ = try await GPGService.shared.ping()
                available = true
            } catch {
                available = GPGServiceConnection.reachability(afterFailedPing: error)
            }
            HostAppReachability.shared.isAvailable = available
            // Unknown answers optimistically, as the callers that didn't ping do.
            completionHandler(Self.encodingStatus(hostAvailable: available ?? true, policy: policy))
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
                    message: GPGXPCError.hostAppNotRunningMessage),
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
            let errors = OutgoingMessage.missingDataErrors(shouldSign: shouldSign, shouldEncrypt: shouldEncrypt)
            completionHandler(MEMessageEncodingResult(
                encodedMessage: nil, signingError: errors.signing, encryptionError: errors.encryption))
            return
        }

        log.info("encode: rawData size=\(body.count) bytes")

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

        // `rawString` is the full RFC 2822 form — "Ravi <ravi@example.com>",
        // display name and angle brackets included. Comparing that to a key's
        // bare email never matches when a display name is present. Use the
        // same normalisation the recipient lookup uses.
        let senderEmail  = message.fromAddress.bareAddress
        let visibleAddresses = (message.toAddresses + message.ccAddresses).map(\.bareAddress)
        let blindAddresses = message.bccAddresses.map(\.bareAddress)

        // Split visible from blind recipients. OpenPGP stamps a key ID into the
        // packet for every recipient, and every recipient can read that list —
        // so encrypting to a BCC address the ordinary way tells the whole To
        // line who else received it. Those go in as hidden recipients instead.
        var recipients = OutgoingMessage.Recipients()
        if shouldEncrypt {
            // Only this window's own state: another window's keys are another
            // message's recipients.
            let state = sessionState(for: message, fallBackToSingleWindow: false)
            switch OutgoingMessage.recipients(
                visible: visibleAddresses, blind: blindAddresses,
                status: state?.recipientKeyStatus,
                fingerprints: (state?.recipientKeys ?? [:]).mapValues(\.fingerprint)) {
            case .success(let resolved):
                recipients = resolved
            case .failure(let problem):
                log.error("encode: refusing to encrypt — \(String(describing: problem), privacy: .private)")
                completionHandler(MEMessageEncodingResult(
                    encodedMessage: nil, signingError: nil,
                    encryptionError: Self.encryptionError(for: problem)))
                return
            }
        }

        // Mail calls encode() more than once per message. The key holds
        // everything that decides the output, so an edited, re-addressed or
        // incomplete copy (MGP-26: a Send's first call has an empty text/plain
        // part) is encoded afresh rather than handed another call's ciphertext.
        let cacheKey = OutgoingMessage.cacheKey(
            messageUUID: header("x-universally-unique-identifier", in: message),
            shouldSign: shouldSign, shouldEncrypt: shouldEncrypt,
            addresses: visibleAddresses + blindAddresses.map { "bcc:" + $0 },
            recipients: recipients, rawData: body)
        if let cached = cachedEncodeResult(for: cacheKey) {
            log.info("encode: cache hit (\(body.count) bytes)")
            completionHandler(cached)
            return
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
                var encryptFingerprints = recipients.visible
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
                        log.info("encode: sign+encrypt to \(encryptFingerprints.count) recipient(s), \(recipients.hidden.count) hidden")
                        encodedData = MEEncodedOutgoingMessage(
                            rawData: try await GPGService.shared.signAndEncrypt(
                                data: body, signerKeyID: signerKey.fingerprint,
                                recipientFingerprints: encryptFingerprints,
                                hiddenRecipientFingerprints: recipients.hidden),
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
                    log.info("encode: encrypt-only to \(encryptFingerprints.count) recipient(s), \(recipients.hidden.count) hidden")
                    encodedData = MEEncodedOutgoingMessage(
                        rawData: try await GPGService.shared.encrypt(
                            data: body, recipientFingerprints: encryptFingerprints,
                            hiddenRecipientFingerprints: recipients.hidden),
                        isSigned: false, isEncrypted: true)
                    log.info("encode: encrypt succeeded")
                }

                log.info("encode: encoded \(encodedData.rawData.count) bytes")

                // Evidence for next time: these addresses demonstrably accept
                // encrypted mail from us.
                if shouldEncrypt {
                    for email in Set(visibleAddresses + blindAddresses) where !email.isEmpty {
                        GPGService.shared.recordEncryptedSend(to: email)
                    }
                }

                let encodeResult = MEMessageEncodingResult(encodedMessage: encodedData, signingError: nil, encryptionError: nil)

                // Cache both the encode result (so subsequent encode calls for
                // the same message return instantly) and a pre-built decoded
                // message (so decodedMessage() on the encrypted output also
                // returns instantly without a GPG decrypt).
                if let cacheKey {
                    self.storeEncodeResult(encodeResult, for: cacheKey)
                }
                // Pre-build the decoded form so Mail's indexer does not decrypt
                // the Sent copy we just produced. Keyed by the hash of the
                // ciphertext, which is exactly the bytes Mail will hand back.
                let signer = signerKey.map {
                    Signer(email: $0.email, keyID: $0.keyID,
                           fingerprint: $0.fingerprint, trustLevel: $0.trustLevel,
                           emails: $0.emails)
                }
                let signers = signer.map { [$0] } ?? []
                let status: SecurityStatus = shouldEncrypt
                    ? .encrypted(signers: signers)
                    : .signed(signers: signers)
                if let decoded = Self.makeDecodedMessage(data: body, status: status,
                                                         wasEncrypted: shouldEncrypt) {
                    self.decodeCache.store(decoded, for: Self.contentKey(encodedData.rawData))
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
    /// Without the header it can fall back to singleActiveState, which is good
    /// enough for deciding what to offer and never for choosing keys.
    /// Uses case-insensitive lookup because Mail normalises header capitalisation.
    private func sessionState(for message: MEMessage, fallBackToSingleWindow: Bool = true) -> ComposeSessionState? {
        if let idString = header("x-mailgpg-sessionid", in: message),
           let uuid = UUID(uuidString: idString) {
            return ComposeStateStore.shared.state(for: uuid)
        }
        return fallBackToSingleWindow ? ComposeStateStore.shared.singleActiveState : nil
    }

    private static func encodeError(code: Int, _ description: String) -> NSError {
        NSError(domain: "net.pyxzl.mailgpg", code: code,
                userInfo: [NSLocalizedDescriptionKey: description])
    }

    private static func encryptionError(for problem: OutgoingMessage.RecipientProblem) -> NSError {
        switch problem {
        case .keyChanged(let emails):
            return encodeError(code: 5,
                "The public key for these recipients is not the one used before:\n\(emails.joined(separator: ", "))\n\n"
              + "This is what key substitution looks like. Confirm the new key's "
              + "fingerprint with the recipient through another channel, then mark it "
              + "verified in Manage Keys to accept it.")
        case .missingKeys(let emails):
            return encodeError(code: 3,
                "The following recipients don't have a public key:\n\(emails.joined(separator: ", "))\n\n"
              + "Turn off encryption to send without it, or add the missing keys.")
        case .stillLoading(let emails):
            return encodeError(code: 4,
                "Still looking up keys for:\n\(emails.joined(separator: ", "))\n\nPlease try again in a moment.")
        case .noComposeState:
            return encodeError(code: 7,
                "MailGPG cannot tell which keys this message was meant for, because its compose "
              + "window is gone. Open the message as a draft and send it from there, or turn off "
              + "encryption.")
        }
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

    /// The first value of header `name`, unfolded.
    private nonisolated static func headerValue(_ name: String, in data: Data) -> String? {
        RawMessage.headerValues(name, in: data).first
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
        let content = RawMessage.pgpContent(of: data)

        log.debug("decodedMessage: \(data.count) bytes — encrypted=\(content.isEncrypted) signed=\(content.isSigned)")

        guard content.isEncrypted || content.isSigned else {
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

        // MailKit requires this method to be synchronous, but our GPG calls are
        // async. `decodeCache` bridges the two: a detached Task does the work and
        // this thread waits, on the decode of the same content already running if
        // there is one. Mail's indexer often calls decodedMessage 10+ times for
        // the same message; once a result is cached, those return instantly.
        do {
            return try decodeCache.decode(key: cacheKey) {
                content.isEncrypted ? await Self.decrypt(data) : await Self.verify(data)
            }
        } catch {
            // Mail serializes decode requests, so a stuck operation (a wedged XPC
            // call, gpg waiting on a pinentry that cannot be shown) must not hold
            // up every message behind it. Mail shows the raw message; the decode
            // carries on, and its result is cached for the next look.
            log.error("decodedMessage: timed out — returning nil, the decode continues")
            return nil
        }
    }

    /// Signed: extract the signed data and detached signature, then call
    /// gpg --verify to check the signature. When the signed entity is itself
    /// multipart/encrypted, it is decrypted too.
    private nonisolated static func verify(_ data: Data) async -> MEDecodedMessage? {
        guard let (signedData, signatureData) = RawMessage.signedParts(of: data) else {
            log.error("decodedMessage: could not extract signed parts from multipart/signed")
            return nil
        }
        log.debug("decodedMessage: verifying signature (\(signedData.count) data bytes, \(signatureData.count) sig bytes)")
        guard let rawStatus = await signatureStatus(signed: signedData, signature: signatureData) else { return nil }
        log.debug("decodedMessage: verify completed")

        // Encrypted inside signed: the signature covers the ciphertext, and
        // the message is the plaintext. When decryption fails, the signed
        // message is shown as it is.
        if RawMessage.isMIMEEncrypted(signedData),
           let (plaintext, decryptStatus) = try? await GPGService.shared.decrypt(
               data: RawMessage.replacingBody(of: data, with: signedData)) {
            log.debug("decodedMessage: decrypted the encrypted entity inside the signature")
            let combined = SecurityStatus.nested(decryption: decryptStatus, signature: rawStatus)
            return makeDecodedMessage(data: plaintext,
                                      status: checkSignerMatchesSender(combined, messageData: data),
                                      wasEncrypted: decryptStatus.isDecrypted,
                                      banner: protectedSubjectBanner(outer: data, plaintext: plaintext))
        }
        return makeDecodedMessage(data: data, status: checkSignerMatchesSender(rawStatus, messageData: data))
    }

    /// gpg --verify of a detached signature. A signature gpg rejects is
    /// `.signatureInvalid`; nil when the helper could not be asked.
    private nonisolated static func signatureStatus(signed: Data, signature: Data) async -> SecurityStatus? {
        do {
            return try await GPGService.shared.verify(data: signed, signature: signature)
        } catch let error as NSError {
            logNSError(error, prefix: "decodedMessage: verify error")
            switch GPGXPCError(nsError: error) {
            case .gpgFailed: return .signatureInvalid(reason: error.localizedDescription)
            default:         return nil
            }
        }
    }

    /// Encrypted (possibly also signed): decrypt.
    private nonisolated static func decrypt(_ data: Data) async -> MEDecodedMessage? {
        do {
            let (plaintext, decryptStatus) = try await GPGService.shared.decrypt(data: data)
            log.debug("decodedMessage: decrypt succeeded")
            var rawStatus = decryptStatus
            // Signed inside encrypted (mutt, KMail): the decrypted entity is
            // multipart/signed, and its signature is not one gpg --decrypt
            // sees. Without verifying it the message read "encrypted, no
            // signer" with a signature.asc attachment.
            if case .encrypted = decryptStatus,
               let (signedData, signatureData) = RawMessage.signedParts(of: plaintext),
               let signature = await signatureStatus(signed: signedData, signature: signatureData) {
                log.debug("decodedMessage: verified the signed entity inside the encryption")
                rawStatus = .nested(decryption: decryptStatus, signature: signature)
            }
            // Check against the envelope's From — that is the address
            // Mail displays, and therefore the claim being made.
            let status = checkSignerMatchesSender(rawStatus, messageData: data)
            return makeDecodedMessage(data: plaintext, status: status,
                                      wasEncrypted: decryptStatus.isDecrypted,
                                      banner: protectedSubjectBanner(outer: data, plaintext: plaintext))
        } catch let error as NSError {
            logNSError(error, prefix: "decodedMessage: decrypt error")
            // Return nil so Mail shows the raw message instead of crashing.
            // Returning a MEDecodedMessage with the original encrypted data
            // causes Mail's indexer to loop and trigger a KVO re-entrancy crash.
            return nil
        }
    }

    /// Protected subject (RFC 3156 / Memory Hole): when the outer subject is
    /// the placeholder "..." and the decrypted message has a real one, show it
    /// in a banner.
    private nonisolated static func protectedSubjectBanner(outer: Data, plaintext: Data) -> MEDecodedMessageBanner? {
        guard let inner = headerValue("subject", in: plaintext),
              let outerSubject = headerValue("subject", in: outer),
              outerSubject == "...", inner != outerSubject else { return nil }
        return MEDecodedMessageBanner(
            title: "🔒 Subject: \(decodeMIMEWords(inner))",
            primaryActionTitle: "",
            dismissable: false)
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
    /// When the address the message claims to come from is none of the signing
    /// key's live user IDs — primary or not — the signature is reported as
    /// invalid with both addresses named.
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

        // A signature without a sender to check it against authenticates
        // nothing Mail shows: no From, two From headers, or one that yields
        // no address all report invalid rather than passing unchecked.
        let fromHeaders = RawMessage.headerValues("from", in: messageData)
        let from = fromHeaders.count == 1 ? bareEmail(inHeaderValue: decodeMIMEWords(fromHeaders[0])) : ""
        guard !from.isEmpty else {
            log.error("signed message without a single usable From address — signature will be reported as invalid")
            return .signatureInvalid(
                reason: "This message has no single sender address, so the signature does not authenticate it.")
        }

        // Trust is the validity of the user ID carrying From, not the key's:
        // a key verified for one address can carry anyone's address unverified.
        if signers.contains(where: { $0.hasAddress(from) }) {
            let vouching = signers.map { $0.vouching(for: from) }
            if case .encrypted = status { return .encrypted(signers: vouching) }
            return .signed(signers: vouching)
        }

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
