// NestedMessageTests.swift
// MailGPGTests – signed inside encrypted and encrypted inside signed, through
// real GPG, the way the extension's decode takes them apart.

import XCTest
@testable import MailGPG

final class NestedMessageTests: XCTestCase {

    var homedir: TempGPGHomedir!
    var svc: GPGServiceImpl!

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

    // MARK: - Helpers

    private func decrypt(_ data: Data) throws -> (plaintext: Data, status: SecurityStatus) {
        var result: (Data?, Data?, Error?)
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: data) { result = ($0, $1, $2); sem.signal() }
        sem.wait()
        XCTAssertNil(result.2, "Decrypt error: \(String(describing: result.2))")
        let status = try xpcDecode(SecurityStatus.self, from: try XCTUnwrap(result.1))
        return (try XCTUnwrap(result.0), status)
    }

    private func verify(_ signed: Data, _ signature: Data) throws -> SecurityStatus {
        var result: (Data?, Error?)
        let sem = DispatchSemaphore(value: 0)
        svc.verify(data: signed, signature: signature) { result = ($0, $1); sem.signal() }
        sem.wait()
        XCTAssertNil(result.1, "Verify error: \(String(describing: result.1))")
        return try xpcDecode(SecurityStatus.self, from: try XCTUnwrap(result.0))
    }

    private func gpgOutput(_ args: [String], input: Data) throws -> Data {
        let (out, err, code) = try homedir.run(args + ["--batch", "--yes", "--trust-model", "always"], input: input)
        XCTAssertEqual(code, 0, "gpg \(args) failed: \(err)")
        return out
    }

    // MARK: - Signed inside encrypted

    /// mutt and KMail sign first, then encrypt the multipart/signed entity.
    /// Stored with LF headers, with CRLF content in the signed body: the
    /// decrypted entity's headers end at its first blank line, not the first
    /// CRLF one inside the body.
    func testMuttStyleSignedThenEncrypted_verifiesTheInnerSignature() throws {
        let part = "Content-Type: text/plain; charset=us-ascii\nContent-Disposition: inline\n\n"
            + "Hello from mutt\r\n\r\n> quoted with CRLF\r\n"
        // RFC 3156 §5: the signature is over the CRLF canonical form.
        let canonical = part.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        let signature = try gpgOutput(["--detach-sign", "--armor", "--local-user", homedir.fingerprint],
                                      input: Data(canonical.utf8))
        let entity = "Content-Type: multipart/signed; micalg=pgp-sha256;\n"
            + "\tprotocol=\"application/pgp-signature\"; boundary=\"mutt1\"\n"
            + "Content-Disposition: inline\n\n"
            + "--mutt1\n\(part)\n--mutt1\n"
            + "Content-Type: application/pgp-signature; name=\"signature.asc\"\n\n"
            + (try XCTUnwrap(String(data: signature, encoding: .utf8))) + "\n--mutt1--\n"
        let ciphertext = try gpgOutput(["--encrypt", "--armor", "--recipient", homedir.fingerprint],
                                       input: Data(entity.utf8))
        let message = "From: \(homedir.email)\nTo: \(homedir.email)\nSubject: mutt\nMIME-Version: 1.0\n"
            + "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"enc1\"\n\n"
            + "--enc1\nContent-Type: application/pgp-encrypted\n\nVersion: 1\n\n"
            + "--enc1\nContent-Type: application/octet-stream\n\n"
            + (try XCTUnwrap(String(data: ciphertext, encoding: .utf8))) + "\n--enc1--\n"

        let (plaintext, decryptStatus) = try decrypt(Data(message.utf8))
        guard case .encrypted(let embedded) = decryptStatus else {
            return XCTFail("Expected .encrypted, got \(decryptStatus)")
        }
        XCTAssertTrue(embedded.isEmpty, "The signature is not one gpg --decrypt sees")

        let (signed, detached) = try XCTUnwrap(RawMessage.signedParts(of: plaintext),
                                               "The decrypted message must still be multipart/signed")
        let status = SecurityStatus.nested(decryption: decryptStatus, signature: try verify(signed, detached))
        guard case .encrypted(let signers) = status else {
            return XCTFail("Expected .encrypted with the inner signer, got \(status)")
        }
        XCTAssertEqual(signers.map(\.email), [homedir.email])
    }

    // MARK: - Encrypted inside signed

    func testEncryptedThenSigned_decryptsTheSignedEntity() throws {
        var encrypted: Data?
        let encSem = DispatchSemaphore(value: 0)
        svc.encrypt(data: GPGCryptoTests.testMessage, recipientFingerprints: [homedir.fingerprint],
                    hiddenRecipientFingerprints: []) { data, _ in encrypted = data; encSem.signal() }
        encSem.wait()
        var signedMessage: Data?
        let signSem = DispatchSemaphore(value: 0)
        svc.sign(data: try XCTUnwrap(encrypted), signerKeyID: homedir.fingerprint) { data, _ in
            signedMessage = data; signSem.signal()
        }
        signSem.wait()
        let message = try XCTUnwrap(signedMessage)

        let (signed, detached) = try XCTUnwrap(RawMessage.signedParts(of: message))
        let signature = try verify(signed, detached)
        XCTAssertTrue(RawMessage.isMIMEEncrypted(signed), "The signed entity is the ciphertext")

        let (plaintext, decryptStatus) = try decrypt(RawMessage.replacingBody(of: message, with: signed))
        XCTAssertTrue(try XCTUnwrap(String(data: plaintext, encoding: .utf8)).contains("Hello, MailGPG!"))
        XCTAssertEqual(RawMessage.headerValues("from", in: plaintext), [homedir.email],
                       "The envelope survives into the decrypted message")
        let status = SecurityStatus.nested(decryption: decryptStatus, signature: signature)
        guard case .encrypted(let signers) = status else {
            return XCTFail("Expected .encrypted with the outer signer, got \(status)")
        }
        XCTAssertEqual(signers.map(\.email), [homedir.email])
    }

    // MARK: - Combining the layers

    private static let alice = Signer(email: "alice@example.com", keyID: "AAAAAAAA",
                                      fingerprint: String(repeating: "A", count: 40), trustLevel: .full)
    private static let bob = Signer(email: "bob@example.com", keyID: "BBBBBBBB",
                                    fingerprint: String(repeating: "B", count: 40), trustLevel: .full)

    func testNested_aFailingLayerIsTheStatus() {
        let invalid = SecurityStatus.signatureInvalid(reason: "bad")
        XCTAssertEqual(SecurityStatus.nested(decryption: .encrypted(signers: [Self.alice]), signature: invalid),
                       invalid)
        XCTAssertEqual(SecurityStatus.nested(decryption: invalid, signature: .signed(signers: [Self.alice])),
                       invalid)
    }

    func testNested_signersOfBothLayersCountOnce() {
        XCTAssertEqual(
            SecurityStatus.nested(decryption: .encrypted(signers: [Self.alice]),
                                  signature: .signed(signers: [Self.bob, Self.alice])),
            .encrypted(signers: [Self.alice, Self.bob]))
    }
}
