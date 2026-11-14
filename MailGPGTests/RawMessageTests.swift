// RawMessageTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class RawMessageTests: XCTestCase {

    private func headerBlock(_ message: String) -> String {
        String(data: RawMessage.headerBlock(in: Data(message.utf8)), encoding: .utf8) ?? ""
    }

    // MARK: - End of headers

    func testHeaderBlock_CRLF() {
        XCTAssertEqual(headerBlock("From: a\r\nTo: b\r\n\r\nBody"), "From: a\r\nTo: b")
    }

    func testHeaderBlock_LF() {
        XCTAssertEqual(headerBlock("From: a\nTo: b\n\nBody"), "From: a\nTo: b")
    }

    /// LF headers followed by a body containing a CRLF blank line (quoted text,
    /// an attached message): the header block ends at the first blank line, not
    /// at the CRLF one inside the body.
    func testHeaderBlock_LFHeadersBodyContainsCRLFBlankLine() {
        let message = "From: a\nTo: b\n\nHello\r\n\r\nX-Injected: yes\r\n"
        XCTAssertEqual(headerBlock(message), "From: a\nTo: b")
    }

    /// Headers never come near 256 KB, so a blank line past that is not
    /// searched for: a pure-CRLF message used to have its whole body scanned
    /// for the LF pair it never contains.
    func testEndOfHeaders_ignoresBlankLineBeyondSearchWindow() {
        let message = Data(("X-Long: " + String(repeating: "a", count: 300 * 1024) + "\n\nBody").utf8)
        XCTAssertNil(RawMessage.endOfHeaders(in: message))
        XCTAssertEqual(RawMessage.headerBlock(in: message).count, 4096)
    }

    func testEndOfHeaders_rangesIndexASlice() {
        let message = Data("Junk\n\nFrom: a\r\n\r\nBody".utf8)
        let part = message[message.index(message.startIndex, offsetBy: 6)...]
        let block = RawMessage.headerBlock(in: part)
        XCTAssertEqual(String(data: block, encoding: .utf8), "From: a")
    }

    // MARK: - PGP detection

    func testPGPContent_plainMail() {
        let content = RawMessage.pgpContent(of: Data("From: a\nContent-Type: text/plain\n\nHello".utf8))
        XCTAssertEqual(content, .init(isEncrypted: false, isSigned: false))
    }

    func testPGPContent_inlinePGPInPlainBody() {
        let message = "From: a\nContent-Type: text/plain\n\n-----BEGIN PGP MESSAGE-----\n\nhQ==\n-----END PGP MESSAGE-----\n"
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: true, isSigned: false))
    }

    func testPGPContent_inlineSignedInPlainBody() {
        let message = "From: a\nContent-Type: text/plain\n\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nHi\n"
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: false, isSigned: true))
    }

    /// A signed message that quotes an armored encrypted block is signed, not
    /// encrypted: taken down the decrypt path it was labelled encrypted and its
    /// real signature was never verified.
    func testPGPContent_signedMessageQuotingEncryptedBlock() {
        let message = """
        From: a@example.com\r
        Content-Type: multipart/signed; micalg=pgp-sha256;\r
         protocol="application/pgp-signature"; boundary="b1"\r
        \r
        --b1\r
        Content-Type: text/plain\r
        \r
        > -----BEGIN PGP MESSAGE-----\r
        > hQIMA...\r
        > -----END PGP MESSAGE-----\r
        --b1\r
        Content-Type: application/pgp-signature\r
        \r
        -----BEGIN PGP SIGNATURE-----\r
        iQ==\r
        -----END PGP SIGNATURE-----\r
        --b1--\r

        """
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: false, isSigned: true))
    }

    func testPGPContent_MIMEEncrypted() {
        let message = """
        From: a@example.com\r
        Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b1"\r
        \r
        --b1\r
        Content-Type: application/pgp-encrypted\r
        \r
        Version: 1\r
        --b1\r
        Content-Type: application/octet-stream\r
        \r
        -----BEGIN PGP MESSAGE-----\r
        hQ==\r
        -----END PGP MESSAGE-----\r
        --b1--\r

        """
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: true, isSigned: false))
    }

    /// LF plaintext whose body talks about PGP/MIME, followed later by a CRLF
    /// blank line: the body is not part of the header block, so it is not
    /// taken for a signed message.
    func testPGPContent_LFPlainMailMentioningPGPMIMEInBody() {
        let message = "From: a\nContent-Type: text/plain\n\n"
            + "Send it as multipart/signed with application/pgp-signature.\r\n\r\nThanks\r\n"
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: false, isSigned: false))
    }
}
