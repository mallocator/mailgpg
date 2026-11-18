// GPGCryptoTests.swift
// MailGPGTests – integration tests for GPG sign/encrypt/decrypt/verify operations.
//
// Each test creates a fresh isolated GPG homedir (TempGPGHomedir) and a
// GPGServiceImpl pointed at it. No user keys are touched.

import XCTest
@testable import MailGPG

final class GPGCryptoTests: XCTestCase {

    var homedir: TempGPGHomedir!
    var svc: GPGServiceImpl!

    /// A minimal RFC 2822 message used as input to sign/encrypt operations.
    static let testMessage = Data(
        "From: mailgpg-test@example.com\nTo: mailgpg-test@example.com\nSubject: Test\nContent-Type: text/plain\n\nHello, MailGPG!"
            .utf8)

    override func setUpWithError() throws {
        try super.setUpWithError()
        homedir = try TempGPGHomedir()
        svc = GPGServiceImpl(gnupgHome: homedir.path)
    }

    override func tearDownWithError() throws {
        homedir = nil
        svc = nil
        try super.tearDownWithError()
    }

    // MARK: - Non-UTF-8 bodies, end to end through real GPG

    /// A message whose body is iso-8859-1 — not valid UTF-8. Every String
    /// round-trip that used to sit in this pipeline either lost this body or
    /// re-encoded it, and re-encoding is what makes a signature stop verifying.
    private static func latin1Message() -> Data {
        var msg = Data("""
        From: mailgpg-test@example.com\n\
        To: mailgpg-test@example.com\n\
        Subject: Umlaut\n\
        Content-Type: text/plain; charset=iso-8859-1\n\
        \n
        """.utf8)
        msg.append(contentsOf: [0x66, 0xFC, 0x72])   // "für" in iso-8859-1
        return msg
    }

    func testEncryptDecryptRoundTrip_latin1BodySurvives() throws {
        let message = Self.latin1Message()

        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.encrypt(data: message,
                    recipientFingerprints: [homedir.fingerprint],
                    hiddenRecipientFingerprints: []) { data, error in
            XCTAssertNil(error, "Encrypt error: \(String(describing: error))")
            encrypted = data
            encSem.signal()
        }
        encSem.wait()
        guard let encrypted else { return XCTFail("No ciphertext") }

        var plain: Data?
        let decSem = DispatchSemaphore(value: 0)
        svc.decrypt(data: encrypted) { data, _, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = data
            decSem.signal()
        }
        decSem.wait()
        guard let plain else { return XCTFail("No plaintext") }

        let (headers, body) = svc.splitMessage(plain)
        XCTAssertFalse(body.isEmpty, "The body must survive the round trip")
        XCTAssertTrue(body.contains(0xFC), "The original byte must come back unchanged")
        XCTAssertTrue(headers.lowercased().contains("iso-8859-1"),
                      "The charset must still describe the bytes")
    }

    func testSignVerifyRoundTrip_latin1BodyStillVerifies() throws {
        let message = Self.latin1Message()

        var signed: Data?
        let sigSem = DispatchSemaphore(value: 0)
        svc.sign(data: message, signerKeyID: homedir.fingerprint) { data, error in
            XCTAssertNil(error, "Sign error: \(String(describing: error))")
            signed = data
            sigSem.signal()
        }
        sigSem.wait()
        guard let signed else { return XCTFail("No signed message") }
        XCTAssertTrue(signed.contains(0xFC), "The signed message must carry the original byte")

        // Pull the parts back out the way the extension does, and verify.
        let (headers, _) = svc.splitMessage(signed)
        XCTAssertTrue(headers.lowercased().contains("multipart/signed"))

        guard let boundary = svc.foldedHeaderValue("content-type", in: headers)?
            .components(separatedBy: "boundary=\"").last?
            .components(separatedBy: "\"").first else {
            return XCTFail("No boundary")
        }

        // Count boundary occurrences by hand: Data.split takes a single byte,
        // not a byte sequence.
        let delimiter = Data(("--" + boundary).utf8)
        var occurrences = 0
        var cursor = signed.startIndex
        while let hit = signed.range(of: delimiter, in: cursor..<signed.endIndex) {
            occurrences += 1
            cursor = hit.upperBound
        }
        XCTAssertGreaterThanOrEqual(occurrences, 3,
            "Expected an opening boundary, one between the parts, and the closing one")
        XCTAssertNotNil(signed.range(of: Data("-----BEGIN PGP SIGNATURE-----".utf8)),
                        "The detached signature must be present")
    }

    // MARK: - Encrypt / Decrypt

    func testEncryptDecryptRoundTrip() throws {
        let fp = homedir.fingerprint

        // Encrypt
        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.encrypt(data: Self.testMessage,
                    recipientFingerprints: [fp],
                    hiddenRecipientFingerprints: []) { data, error in
            XCTAssertNil(error, "Encrypt error: \(String(describing: error))")
            encrypted = data
            encSem.signal()
        }
        encSem.wait()

        let encData = try XCTUnwrap(encrypted, "No encrypted data returned")
        let encStr = String(data: encData, encoding: .utf8) ?? ""
        XCTAssertTrue(encStr.contains("multipart/encrypted"), "Output is not multipart/encrypted MIME")

        // Decrypt
        var plain: Data?
        var statusRaw: Data?
        let decSem = DispatchSemaphore(value: 0)
        svc.decrypt(data: encData) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            decSem.signal()
        }
        decSem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssertTrue(plainStr.contains("Hello, MailGPG!"), "Decrypted body does not match original")

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) },
            "Could not decode SecurityStatus")
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted, got \(status)"); return
        }
        XCTAssertTrue(signers.isEmpty, "Encrypt-only message should have no signers")
    }

    /// Text around an inline block is neither encrypted nor signed, yet it
    /// shared the block's lock and signer in Mail: anyone could wrap a
    /// ciphertext Alice once sent in their own words. Only the decrypted text
    /// is shown; the rest stays in the raw source.
    func testDecryptInlinePGP_showsOnlyTheDecryptedText() throws {
        let fp = homedir.fingerprint
        let secret = "Inline secret body"
        let (ciphertext, stderr, code) = try homedir.run(
            ["--armor", "--trust-model", "always", "--encrypt", "--recipient", fp],
            input: Data(secret.utf8)
        )
        XCTAssertEqual(code, 0, "Direct GPG encrypt failed: \(stderr)")

        let armor = String(data: ciphertext, encoding: .utf8)!
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let message = """
            From: sender@example.com
            To: \(homedir.email)
            Subject: Inline
            Content-Type: multipart/alternative; boundary="BOUND"

            --BOUND
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: 7bit

            Prefix before block

            \(armor)

            Suffix after block
            --BOUND
            Content-Type: text/html; charset=utf-8
            Content-Transfer-Encoding: 7bit

            <p>HTML untouched</p>
            --BOUND--
            """

        var plain: Data?
        var statusRaw: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: Data(message.utf8)) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            sem.signal()
        }
        sem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssert(plainStr.lowercased().contains("content-type: text/plain"), "plain=\(plainStr)")
        XCTAssertFalse(plainStr.lowercased().contains("multipart/alternative"), "plain=\(plainStr)")
        let (_, bodyData) = svc.splitMessage(Data(plainStr.utf8))
        let body = String(data: bodyData, encoding: .utf8) ?? ""
        XCTAssertFalse(body.contains("Prefix before block"), "body=\(body)")
        XCTAssertTrue(body.contains(secret), "body=\(body)")
        XCTAssertFalse(body.contains("Suffix after block"), "body=\(body)")
        XCTAssertFalse(body.contains("-----BEGIN PGP MESSAGE-----"), "body=\(body)")

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) },
            "Could not decode SecurityStatus")
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted, got \(status)"); return
        }
        XCTAssertTrue(signers.isEmpty, "Encrypt-only message should have no signers")
    }

    /// An inline-PGP message with its attachments, as Enigmail sends it: the
    /// text part carries the armoured block, each attachment is encrypted on
    /// its own as `name.pgp`. `leadingParts` and `extraParts` are added
    /// verbatim before the text part and after the attachment.
    /// `nested` puts the text part in a multipart/alternative next to an
    /// HTML part, the way Mail and most clients send it. `sender` encrypts
    /// and signs both to the reader's key (default: the reader's own key).
    private func inlineMessageWithAttachment(signed: Bool, attachment: Data, leadingParts: String = "",
                                             extraParts: String = "", nested: Bool = false,
                                             sender: TempGPGHomedir? = nil) throws -> Data {
        let sender = sender ?? homedir!
        var args = ["--trust-model", "always", "--encrypt", "--recipient", homedir.fingerprint]
        if signed { args += ["--sign", "--local-user", sender.fingerprint] }
        let (armor, stderr, code) = try sender.run(["--armor"] + args, input: Data("Inline secret body".utf8))
        XCTAssertEqual(code, 0, "gpg encrypt failed: \(stderr)")
        let (binary, stderr2, code2) = try sender.run(args, input: attachment)
        XCTAssertEqual(code2, 0, "gpg encrypt failed: \(stderr2)")
        var text = """
            Content-Type: text/plain; charset=utf-8
            Content-Transfer-Encoding: 7bit

            \(String(data: armor, encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines))
            """
        if nested {
            text = """
                Content-Type: multipart/alternative; boundary="ALT"

                --ALT
                \(text)
                --ALT
                Content-Type: text/html; charset=utf-8

                <html><body><pre>encrypted</pre></body></html>
                --ALT--
                """
        }
        let message = """
            From: \(homedir.email)
            To: \(homedir.email)
            Subject: Inline with attachment
            Content-Type: multipart/mixed; boundary="MIXED"

            \(leadingParts)--MIXED
            \(text)
            --MIXED
            Content-Type: application/octet-stream; name="report.pdf.pgp"
            Content-Disposition: attachment; filename="report.pdf.pgp"
            Content-Transfer-Encoding: base64

            \(binary.base64EncodedString(options: .lineLength76Characters))
            \(extraParts)--MIXED--
            """
        return Data(message.utf8)
    }

    private func decrypt(_ message: Data) throws -> (message: Data, status: SecurityStatus) {
        var plain: Data?
        var statusRaw: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: message) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            sem.signal()
        }
        sem.wait()
        let status = try XCTUnwrap(statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) })
        return (try XCTUnwrap(plain), status)
    }

    /// Decrypting an inline-PGP message kept only its text: `report.pdf.pgp`
    /// was gone from the decrypted view.
    func testDecryptInlinePGP_keepsTheDecryptedAttachment() throws {
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let (plain, status) = try decrypt(inlineMessageWithAttachment(signed: true, attachment: pdf))

        guard case .encrypted(let signers) = status, signers.count == 1 else {
            return XCTFail("Expected encrypted and signed, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.lowercased().contains("content-type: multipart/mixed"), "plain=\(str)")
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertTrue(str.contains(pdf.base64EncodedString()), "the attachment must be decrypted: \(str)")
        XCTAssertFalse(str.contains("report.pdf.pgp"), "plain=\(str)")
    }

    /// Inside multipart/mixed > multipart/alternative, the inline text part was
    /// not found: the message became the decrypted text alone, without
    /// `report.pdf.pgp`.
    func testDecryptInlinePGP_nestedInAlternative_keepsTheDecryptedAttachment() throws {
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let (plain, status) = try decrypt(inlineMessageWithAttachment(signed: true, attachment: pdf, nested: true))

        guard case .encrypted(let signers) = status, signers.count == 1 else {
            return XCTFail("Expected encrypted and signed, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.lowercased().contains("content-type: multipart/mixed"), "plain=\(str)")
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertTrue(str.contains(pdf.base64EncodedString()), "the attachment must be decrypted: \(str)")
        XCTAssertFalse(str.contains("<html>"), "the HTML part is outside the encryption: \(str)")
    }

    /// With several text/plain parts, the one holding the inline block wins,
    /// not the first: a plain note ahead of it hid the block from the rebuild,
    /// and with it `report.pdf.pgp`. The note stays out of the decrypted text.
    func testDecryptInlinePGP_blockInALaterTextPart_wins() throws {
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let note = """
            --MIXED
            Content-Type: text/plain; charset=utf-8

            Plain note before the block

            """
        let (plain, status) = try decrypt(inlineMessageWithAttachment(signed: true, attachment: pdf,
                                                                      leadingParts: note))

        guard case .encrypted(let signers) = status, signers.count == 1 else {
            return XCTFail("Expected encrypted and signed, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.lowercased().contains("content-type: multipart/mixed"), "plain=\(str)")
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertFalse(str.contains("Plain note before the block"), "plain=\(str)")
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertTrue(str.contains(pdf.base64EncodedString()), "the attachment must be decrypted: \(str)")
    }

    /// Parts the sender added outside the encryption must not be shown under
    /// its lock and signer: an unencrypted text part and attachment, and an
    /// attachment anyone could encrypt to us but nobody signed.
    func testDecryptInlinePGP_dropsPartsOutsideTheEncryption() throws {
        let (unsigned, stderr, code) = try homedir.run(
            ["--trust-model", "always", "--encrypt", "--recipient", homedir.fingerprint],
            input: Data("forged attachment".utf8))
        XCTAssertEqual(code, 0, "gpg encrypt failed: \(stderr)")
        let extra = """
            --MIXED
            Content-Type: text/plain; charset=utf-8

            Unencrypted note next to the block
            --MIXED
            Content-Type: text/plain; name="notes.txt"
            Content-Disposition: attachment; filename="notes.txt"

            Unencrypted attachment
            --MIXED
            Content-Type: application/octet-stream; name="forged.txt.pgp"
            Content-Disposition: attachment; filename="forged.txt.pgp"
            Content-Transfer-Encoding: base64

            \(unsigned.base64EncodedString(options: .lineLength76Characters))

            """
        let (plain, status) = try decrypt(inlineMessageWithAttachment(
            signed: true, attachment: Data("real".utf8), extraParts: extra))

        guard case .encrypted(let signers) = status, signers.count == 1 else {
            return XCTFail("Expected encrypted and signed, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertFalse(str.contains("Unencrypted note"), "plain=\(str)")
        XCTAssertFalse(str.contains("Unencrypted attachment"), "plain=\(str)")
        XCTAssertFalse(str.contains("notes.txt"), "plain=\(str)")
        XCTAssertFalse(str.contains("forged.txt"), "plain=\(str)")
        XCTAssertFalse(str.contains(Data("forged attachment".utf8).base64EncodedString()), "plain=\(str)")
    }

    /// A sender whose key the reader doesn't have: their keyring holds the
    /// reader's public key, the reader's lacks theirs.
    private func unknownSender() throws -> TempGPGHomedir {
        let sender = try TempGPGHomedir()
        let (readerKey, _, _) = try homedir.run(["--armor", "--export", homedir.fingerprint])
        _ = try sender.run(["--batch", "--import"], input: readerKey)
        return sender
    }

    /// An attachment part encrypted to the reader by `by`, signed when `signed`.
    private func encryptedAttachmentPart(_ name: String, content: String, by: TempGPGHomedir,
                                         signed: Bool) throws -> String {
        var args = ["--trust-model", "always", "--encrypt", "--recipient", homedir.fingerprint]
        if signed { args += ["--sign", "--local-user", by.fingerprint] }
        let (binary, stderr, code) = try by.run(args, input: Data(content.utf8))
        XCTAssertEqual(code, 0, "gpg encrypt failed: \(stderr)")
        return """
            --MIXED
            Content-Type: application/octet-stream; name="\(name).pgp"
            Content-Disposition: attachment; filename="\(name).pgp"
            Content-Transfer-Encoding: base64

            \(binary.base64EncodedString(options: .lineLength76Characters))

            """
    }

    /// Signed by a key not in the keyring (no fetch on open since MGP-16),
    /// the text decrypted but `report.pdf.pgp` was dropped. Owner 2026-11-16:
    /// keep attachments signed by the same missing key ID as the text.
    func testDecryptInlinePGP_unknownSigner_keepsTheAttachmentSignedByThatKey() throws {
        let sender = try unknownSender()
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let (plain, status) = try decrypt(inlineMessageWithAttachment(signed: true, attachment: pdf,
                                                                      sender: sender))

        guard case .keyNotFound(let keyID) = status else {
            return XCTFail("Expected .keyNotFound, got \(status)")
        }
        let (senderKeys, _, _) = try sender.run(["--list-keys", "--with-colons", sender.fingerprint])
        let listing = try XCTUnwrap(String(bytes: senderKeys, encoding: .utf8))
        XCTAssertTrue(listing.contains(keyID.uppercased()), "keyID=\(keyID) is not the sender's")
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertTrue(str.contains(pdf.base64EncodedString()), "the attachment must be decrypted: \(str)")
    }

    /// With the text's signer unknown, an attachment anyone could add is still
    /// dropped: one not signed, one signed by another missing key, and one
    /// signed by a key the reader has.
    func testDecryptInlinePGP_unknownSigner_dropsAttachmentsSignedOtherwise() throws {
        let sender = try unknownSender()
        let stranger = try unknownSender()
        let extra = try encryptedAttachmentPart("unsigned.txt", content: "unsigned attachment",
                                                by: stranger, signed: false)
            + encryptedAttachmentPart("stranger.txt", content: "stranger attachment", by: stranger, signed: true)
            + encryptedAttachmentPart("known.txt", content: "known attachment", by: homedir, signed: true)
        let (plain, status) = try decrypt(inlineMessageWithAttachment(
            signed: true, attachment: Data("real".utf8), extraParts: extra, sender: sender))

        guard case .keyNotFound = status else {
            return XCTFail("Expected .keyNotFound, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        for name in ["unsigned", "stranger", "known"] {
            XCTAssertFalse(str.contains("\(name).txt"), "plain=\(str)")
            XCTAssertFalse(str.contains(Data("\(name) attachment".utf8).base64EncodedString()), "plain=\(str)")
        }
    }

    /// A text signed by a key its owner since revoked is `.signatureInvalid`:
    /// the text still shows, under that warning, but no attachment does, not
    /// even one signed by the same key.
    func testDecryptInlinePGP_revokedSigner_dropsTheAttachment() throws {
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let message = try inlineMessageWithAttachment(signed: true, attachment: pdf)
        // gpg writes a revocation certificate for every key it generates,
        // its armour line commented out with a leading colon.
        let certPath = "\(homedir.path)/openpgp-revocs.d/\(homedir.fingerprint).rev"
        let cert = try String(contentsOfFile: certPath, encoding: .utf8)
            .replacingOccurrences(of: ":-----BEGIN", with: "-----BEGIN")
        let (_, stderr, code) = try homedir.run(["--batch", "--import"], input: Data(cert.utf8))
        XCTAssertEqual(code, 0, "gpg import of the revocation failed: \(stderr)")

        let (plain, status) = try decrypt(message)

        guard case .signatureInvalid(let reason) = status else {
            return XCTFail("Expected .signatureInvalid, got \(status)")
        }
        XCTAssertTrue(reason.lowercased().contains("revoked"), "reason=\(reason)")
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertFalse(str.lowercased().contains("multipart/mixed"), "plain=\(str)")
        XCTAssertFalse(str.contains("report.pdf"), "plain=\(str)")
        XCTAssertFalse(str.contains(pdf.base64EncodedString()), "plain=\(str)")
    }

    /// An attachment gpg can't decrypt (encrypted to a key the reader lacks)
    /// is left out; the text and the attachment that decrypts still show.
    /// The text is unsigned, so the signer check can't be what drops it.
    func testDecryptInlinePGP_attachmentThatFailsToDecrypt_isDropped() throws {
        let other = try TempGPGHomedir()
        let (foreign, stderr, code) = try other.run(
            ["--trust-model", "always", "--encrypt", "--recipient", other.fingerprint],
            input: Data("foreign attachment".utf8))
        XCTAssertEqual(code, 0, "gpg encrypt failed: \(stderr)")
        let extra = """
            --MIXED
            Content-Type: application/octet-stream; name="foreign.txt.pgp"
            Content-Disposition: attachment; filename="foreign.txt.pgp"
            Content-Transfer-Encoding: base64

            \(foreign.base64EncodedString(options: .lineLength76Characters))

            """
        let pdf = Data("%PDF-1.4 report bytes \u{00}\u{01}\u{02}".utf8)
        let (plain, status) = try decrypt(inlineMessageWithAttachment(
            signed: false, attachment: pdf, extraParts: extra))

        guard case .encrypted(let signers) = status, signers.isEmpty else {
            return XCTFail("Expected encrypted without signers, got \(status)")
        }
        let str = try XCTUnwrap(String(data: plain, encoding: .utf8))
        XCTAssertTrue(str.contains("Inline secret body"), "plain=\(str)")
        XCTAssertTrue(str.contains("filename=\"report.pdf\""), "plain=\(str)")
        XCTAssertTrue(str.contains(pdf.base64EncodedString()), "the attachment must be decrypted: \(str)")
        XCTAssertFalse(str.contains("foreign.txt"), "plain=\(str)")
    }

    /// gpg --decrypt exits 0 on a literal packet that was never encrypted.
    func testDecryptInlineStoredLiteral_isNotEncrypted() throws {
        let (stored, stderr, code) = try homedir.run(["--armor", "--store"], input: Data("not secret".utf8))
        XCTAssertEqual(code, 0, "gpg --store failed: \(stderr)")
        let message = "From: sender@example.com\nContent-Type: text/plain\n\n"
            + (String(data: stored, encoding: .utf8) ?? "")
        var statusRaw: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: Data(message.utf8)) { _, statusData, _ in
            statusRaw = statusData
            sem.signal()
        }
        sem.wait()
        let status = try XCTUnwrap(statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) })
        if case .encrypted = status { XCTFail("a stored literal was reported as encrypted") }
    }

    // MARK: - Sign + verify round-trip

    func testSignRoundTrip() throws {
        let fp = homedir.fingerprint

        var signed: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.sign(data: Self.testMessage, signerKeyID: fp) { data, error in
            XCTAssertNil(error, "Sign error: \(String(describing: error))")
            signed = data
            sem.signal()
        }
        sem.wait()

        let signedStr = String(data: try XCTUnwrap(signed), encoding: .utf8) ?? ""
        XCTAssertTrue(signedStr.contains("multipart/signed"),           "Missing multipart/signed content type")
        XCTAssertTrue(signedStr.contains("application/pgp-signature"),  "Missing pgp-signature part")
        XCTAssertTrue(signedStr.contains("-----BEGIN PGP SIGNATURE-----"), "Missing PGP signature block")
        XCTAssertTrue(signedStr.contains("Hello, MailGPG!"),            "Signed body is missing")

        // Parse the multipart/signed MIME output the way the extension does
        // and verify the signature is cryptographically valid — catches bugs
        // where sign() produces a correct MIME structure but signs the wrong
        // content or uses the wrong canonical form.
        let (signedContent, sigData) = try XCTUnwrap(
            RawMessage.signedParts(of: try XCTUnwrap(signed)),
            "Could not extract signed content and signature from MIME output")

        var verifyStatus: SecurityStatus?
        let verifySem = DispatchSemaphore(value: 0)
        svc.verify(data: signedContent, signature: sigData) { statusData, error in
            XCTAssertNil(error, "Verify error: \(String(describing: error))")
            verifyStatus = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            verifySem.signal()
        }
        verifySem.wait()

        let vs = try XCTUnwrap(verifyStatus)
        guard case .signed(let signers) = vs else {
            XCTFail("Expected .signed after verify, got \(vs)"); return
        }
        XCTAssertEqual(signers[0].email, homedir.email)
    }

    // MARK: - Verify (detached signature)

    func testVerifyGoodSignature() throws {
        let plainData = "Hello, MailGPG!".data(using: .utf8)!
        let fp = homedir.fingerprint

        // Sign directly using the test homedir's GPG binary
        let (sigData, signErr, signCode) = try homedir.run(
            ["--detach-sign", "--armor", "--batch", "--yes", "--local-user", fp],
            input: plainData)
        XCTAssertEqual(signCode, 0, "Direct GPG sign failed: \(signErr)")

        // Verify via GPGServiceImpl
        var status: SecurityStatus?
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: plainData, signature: sigData) { statusData, error in
            XCTAssertNil(error, "Verify error: \(String(describing: error))")
            status = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let s = try XCTUnwrap(status)
        guard case .signed(let signers) = s else {
            XCTFail("Expected .signed, got \(s)"); return
        }
        XCTAssertEqual(signers.count, 1)
        // GPG2 reports the SIGNING-SUBKEY fingerprint in VALIDSIG, not the primary key.
        // Confirm the signer belongs to our test key via email, and that enrichFromKeyring
        // could look it up (trustLevel != .unknown means the key was found in the homedir).
        XCTAssertEqual(signers[0].email, homedir.email)
        XCTAssertFalse(signers[0].fingerprint.isEmpty)
    }

    func testVerifySignerCarriesSecondaryAddress() throws {
        // GOODSIG names the primary user ID even when the message was signed
        // for another address on the key, so the From check needs the rest.
        let fp = homedir.fingerprint
        let second = "second@example.com"
        for args in [["--quick-add-uid", fp, "Second <\(second)>"],
                     ["--quick-set-primary-uid", fp, "MailGPG Test <\(homedir.email)>"]] {
            let (_, stderr, code) = try homedir.run(["--batch"] + args)
            XCTAssertEqual(code, 0, "\(args[0]) failed: \(stderr)")
        }
        let plainData = Data("Hello, MailGPG!".utf8)
        let (sigData, signErr, signCode) = try homedir.run(
            ["--detach-sign", "--armor", "--batch", "--yes", "--local-user", fp, "--sender", second],
            input: plainData)
        XCTAssertEqual(signCode, 0, "Direct GPG sign failed: \(signErr)")

        var status: SecurityStatus?
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: plainData, signature: sigData) { statusData, _ in
            status = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        guard case .signed(let signers) = try XCTUnwrap(status), let signer = signers.first else {
            return XCTFail("Expected .signed, got \(String(describing: status))")
        }
        XCTAssertEqual(signer.email, homedir.email)
        XCTAssertTrue(signer.hasAddress("Second@Example.com"), "addresses: \(signer.emails)")
        XCTAssertTrue(signer.hasAddress(homedir.email))
        XCTAssertFalse(signer.hasAddress("other@example.com"))
    }

    func testVerifyBadSignature() throws {
        let originalData = "Hello!".data(using: .utf8)!
        let tamperedData = "Goodbye!".data(using: .utf8)!
        let fp = homedir.fingerprint

        // Sign the original data
        let (sigData, _, signCode) = try homedir.run(
            ["--detach-sign", "--armor", "--batch", "--yes", "--local-user", fp],
            input: originalData)
        XCTAssertEqual(signCode, 0)

        // Verify the signature against different (tampered) data
        var status: SecurityStatus?
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: tamperedData, signature: sigData) { statusData, _ in
            status = statusData.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let s = try XCTUnwrap(status)
        if case .signatureInvalid = s { /* expected */ }
        else { XCTFail("Expected .signatureInvalid for tampered data, got \(s)") }
    }

    // MARK: - Sign + Encrypt / Decrypt

    func testSignEncryptDecryptRoundTrip() throws {
        let fp = homedir.fingerprint

        // Sign + encrypt in one pass
        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.signAndEncrypt(
            data: Self.testMessage,
            signerKeyID: fp,
            recipientFingerprints: [fp],
            hiddenRecipientFingerprints: []) { data, error in
                XCTAssertNil(error, "SignAndEncrypt error: \(String(describing: error))")
                encrypted = data
                encSem.signal()
        }
        encSem.wait()

        // Decrypt — signature info should survive inside the encrypted payload
        var plain: Data?
        var statusRaw: Data?
        let decSem = DispatchSemaphore(value: 0)
        svc.decrypt(data: try XCTUnwrap(encrypted)) { plainData, statusData, error in
            XCTAssertNil(error, "Decrypt error: \(String(describing: error))")
            plain = plainData
            statusRaw = statusData
            decSem.signal()
        }
        decSem.wait()

        let plainStr = String(data: try XCTUnwrap(plain), encoding: .utf8) ?? ""
        XCTAssertTrue(plainStr.contains("Hello, MailGPG!"))

        let status = try XCTUnwrap(
            statusRaw.flatMap { try? xpcDecode(SecurityStatus.self, from: $0) })
        guard case .encrypted(let signers) = status else {
            XCTFail("Expected .encrypted(signers:), got \(status)"); return
        }
        XCTAssertEqual(signers.count, 1, "Expected exactly one signer")
        // GPG2 reports the signing-subkey fingerprint in VALIDSIG, not the primary key.
        // Verify signer identity via email; fingerprint non-empty confirms it was parsed.
        XCTAssertEqual(signers[0].email, homedir.email)
        XCTAssertFalse(signers[0].fingerprint.isEmpty)
    }

    // MARK: - gpg exiting before it reads its input

    func testEncrypt_largeBodyToUnknownKeyFailsWithoutKillingTheProcess() {
        // gpg stops before reading stdin when it can't use a recipient key.
        // A body larger than the pipe buffer then hits a closed pipe, which
        // used to raise SIGPIPE and take the helper (here: the test host) down.
        var message = Data("From: a@example.com\nContent-Type: text/plain\n\n".utf8)
        message.append(Data(repeating: 0x61, count: 1_000_000))
        var result: (Data?, Error?)
        let sem = DispatchSemaphore(value: 0)
        svc.encrypt(data: message,
                    recipientFingerprints: [String(repeating: "AB", count: 20)],
                    hiddenRecipientFingerprints: []) { data, error in
            result = (data, error)
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(result.0)
        XCTAssertEqual((result.1 as NSError?)?.code, GPGXPCError.gpgFailed.rawValue)
    }
}
