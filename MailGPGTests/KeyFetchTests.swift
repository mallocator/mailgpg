// KeyFetchTests.swift
// MailGPGTests – no key lookup when a mail opens; fetching is the reader's call.

import XCTest
@testable import MailGPG

final class KeyFetchTests: XCTestCase {

    /// The reader's homedir and the sender's, each with its own key. The
    /// reader's keyring lacks the sender's public key.
    var reader: TempGPGHomedir!
    var sender: TempGPGHomedir!

    override func setUpWithError() throws {
        try super.setUpWithError()
        reader = try TempGPGHomedir()
        sender = try TempGPGHomedir()
        let (readerKey, _, _) = try reader.run(["--armor", "--export", reader.fingerprint])
        _ = try sender.run(["--batch", "--import"], input: readerKey)
    }

    override func tearDownWithError() throws {
        reader = nil
        sender = nil
        try super.tearDownWithError()
    }

    /// A mail from the sender, signed with their key and encrypted to the reader.
    private func signedAndEncryptedMail() throws -> Data {
        let message = Data(
            "From: alice@example.invalid\nTo: \(reader.email)\nSubject: Hi\nContent-Type: text/plain\n\nHello"
                .utf8)
        var encrypted: Data?
        let sem = DispatchSemaphore(value: 0)
        GPGServiceImpl(gnupgHome: sender.path).signAndEncrypt(
            data: message, signerKeyID: sender.fingerprint,
            recipientFingerprints: [reader.fingerprint],
            hiddenRecipientFingerprints: []) { data, error in
                XCTAssertNil(error)
                encrypted = data
                sem.signal()
        }
        sem.wait()
        return try XCTUnwrap(encrypted)
    }

    private func decryptStatus(_ mail: Data, with svc: GPGServiceImpl) throws -> SecurityStatus {
        var statusRaw: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.decrypt(data: mail) { _, statusData, error in
            XCTAssertNil(error)
            statusRaw = statusData
            sem.signal()
        }
        sem.wait()
        return try xpcDecode(SecurityStatus.self, from: try XCTUnwrap(statusRaw))
    }

    /// A lookup on decrypt tells the sender's domain (WKD) or a keyserver when
    /// and from where the mail was read, past Mail Privacy Protection.
    func testDecrypt_doesNotLookUpTheUnknownSignerKey() throws {
        let keyserver = try LocalKeyserver()
        let svc = GPGServiceImpl(gnupgHome: reader.path, keyservers: [keyserver.url])

        let status = try decryptStatus(try signedAndEncryptedMail(), with: svc)

        guard case .keyNotFound = status else {
            XCTFail("Expected .keyNotFound, got \(status)"); return
        }
        XCTAssertEqual(keyserver.requests, 0, "decrypt went to the keyserver")
    }

    /// The reader fetches the key on request; the signature then verifies.
    func testFetchKey_importsTheSignerKeyFromTheKeyserver() throws {
        let (senderKey, _, _) = try sender.run(["--armor", "--export", sender.fingerprint])
        let keyserver = try LocalKeyserver(armoredKey: try XCTUnwrap(String(bytes: senderKey, encoding: .utf8)))
        let svc = GPGServiceImpl(gnupgHome: reader.path, keyservers: [keyserver.url])
        let mail = try signedAndEncryptedMail()
        guard case .keyNotFound(let keyID) = try decryptStatus(mail, with: svc) else {
            XCTFail("Expected .keyNotFound before the fetch"); return
        }

        var fetched: Data?
        let sem = DispatchSemaphore(value: 0)
        svc.fetchKey(keyID: keyID) { keyInfoJSON, error in
            XCTAssertNil(error)
            fetched = keyInfoJSON
            sem.signal()
        }
        sem.wait()

        let key = try xpcDecode(KeyInfo.self, from: try XCTUnwrap(fetched))
        XCTAssertEqual(key.fingerprint, sender.fingerprint)
        XCTAssertEqual(keyserver.requests, 1)
        guard case .encrypted(let signers) = try decryptStatus(mail, with: svc) else {
            XCTFail("Expected .encrypted after the fetch"); return
        }
        XCTAssertEqual(signers.count, 1)
    }

    func testFetchKey_rejectsAnInvalidKeyID() {
        var result: (Data?, Error?)
        let sem = DispatchSemaphore(value: 0)
        GPGServiceImpl(gnupgHome: reader.path, keyservers: []).fetchKey(keyID: "--import") {
            result = ($0, $1)
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(result.0)
        XCTAssertNotNil(result.1)
    }
}
