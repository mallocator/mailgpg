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

    // MARK: - Signed parts

    private static let signedMessage = """
    From: alice@example.com\r
    Content-Type: multipart/signed; micalg=pgp-sha256;\r
     protocol="application/pgp-signature"; boundary="b1"\r
    \r
    --b1\r
    Content-Type: text/plain\r
    \r
    Hello, see --b1 here\r
    --b1\r
    Content-Type: application/pgp-signature\r
    \r
    -----BEGIN PGP SIGNATURE-----\r
    iQ==\r
    -----END PGP SIGNATURE-----\r
    --b1--\r

    """

    func testSignedParts_standardMessage() throws {
        // A boundary string in the middle of a line is text, not a delimiter.
        let parts = try XCTUnwrap(RawMessage.signedParts(of: Data(Self.signedMessage.utf8)))
        XCTAssertEqual(String(data: parts.signed, encoding: .utf8),
                       "Content-Type: text/plain\r\n\r\nHello, see --b1 here")
        XCTAssertEqual(String(data: parts.signature, encoding: .utf8),
                       "-----BEGIN PGP SIGNATURE-----\r\niQ==\r\n-----END PGP SIGNATURE-----")
    }

    /// The bytes that are verified must be the part Mail displays. A boundary
    /// taken from another header let a genuine signed part, hidden in the
    /// preamble, vouch for the attacker's text that Mail shows.
    func testSignedParts_boundaryComesFromContentTypeOnly() throws {
        let message = """
        From: alice@example.com
        X-A: boundary="AAA"
        Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="BBB"

        --AAA
        Content-Type: text/plain

        Alice's real words
        --AAA
        Content-Type: application/pgp-signature

        -----BEGIN PGP SIGNATURE-----
        ALICE
        -----END PGP SIGNATURE-----
        --AAA--
        --BBB
        Content-Type: text/plain

        Attacker's words
        --BBB
        Content-Type: application/pgp-signature

        -----BEGIN PGP SIGNATURE-----
        ALICE
        -----END PGP SIGNATURE-----
        --BBB--

        """
        let parts = try XCTUnwrap(RawMessage.signedParts(of: Data(message.utf8)))
        let signed = String(data: parts.signed, encoding: .utf8) ?? ""
        XCTAssertTrue(signed.contains("Attacker's words"), signed)
        XCTAssertFalse(signed.contains("Alice's real words"), signed)
    }

    /// A reply quoting a clearsigned mail is not a multipart/signed message,
    /// and must not get a verdict as one.
    func testSignedParts_multipartAlternativeQuotingClearsignedText() {
        let message = """
        From: bob@example.com
        Content-Type: multipart/alternative; boundary="alt"

        --alt
        Content-Type: text/plain

        > -----BEGIN PGP SIGNED MESSAGE-----
        > Hi
        --alt
        Content-Type: text/html

        <p>Hi</p>
        --alt--

        """
        XCTAssertNil(RawMessage.signedParts(of: Data(message.utf8)))
    }

    func testPGPContent_otherHeaderMentioningMultipartSignedIsNotSigned() {
        let message = "From: a\nX-Note: multipart/signed; protocol=\"application/pgp-signature\"\n"
            + "Content-Type: text/plain\n\nHello"
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: false, isSigned: false))
    }

    func testPGPContent_secondContentTypeIsNotTrusted() {
        // Which of two Content-Type headers Mail uses is not ours to guess.
        let message = "From: a\nContent-Type: text/plain\n"
            + "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"b1\"\n\nHello"
        XCTAssertEqual(RawMessage.pgpContent(of: Data(message.utf8)), .init(isEncrypted: false, isSigned: false))
        XCTAssertNil(RawMessage.signedParts(of: Data(message.utf8)))
    }

    // MARK: - Nested entities

    func testIsMIMEEncrypted_readsTheContentTypeOnly() {
        let encrypted = "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=x\n\n--x"
        XCTAssertTrue(RawMessage.isMIMEEncrypted(Data(encrypted.utf8)))
        // Quoted armour in a signed text part is text, not ciphertext to open.
        let quoting = "Content-Type: text/plain\n\n-----BEGIN PGP MESSAGE-----\nhEwD\n-----END PGP MESSAGE-----"
        XCTAssertFalse(RawMessage.isMIMEEncrypted(Data(quoting.utf8)))
    }

    func testReplacingBody_keepsTheEnvelopeAndTakesTheEntitysContentHeaders() {
        let message = "From: alice@example.com\nSubject: Hi\n there\nContent-Type: multipart/signed;\n boundary=s\n"
            + "Content-Transfer-Encoding: 7bit\nMIME-Version: 1.0\n\n--s\nbody"
        let entity = "Content-Type: multipart/encrypted; boundary=e\n\n--e\ncipher\n"
        let result = String(data: RawMessage.replacingBody(of: Data(message.utf8), with: Data(entity.utf8)),
                            encoding: .utf8)
        XCTAssertEqual(result, "From: alice@example.com\r\nSubject: Hi\r\n there\r\nMIME-Version: 1.0\r\n"
                       + "Content-Type: multipart/encrypted; boundary=e\r\n\r\n--e\r\ncipher\r\n")
    }

    // MARK: - Header values

    func testHeaderValues_unfoldsAFoldedFrom() {
        // Mail unfolds this and shows alice@bank.example as the sender.
        let message = "From:\r\n alice@bank.example\r\nTo: bob@example.com\r\n\r\nHi"
        XCTAssertEqual(RawMessage.headerValues("from", in: Data(message.utf8)), ["alice@bank.example"])
    }

    func testHeaderValues_listsEveryOccurrence() {
        let message = "From: a@example.com\nFrom: b@example.com\n\nHi"
        XCTAssertEqual(RawMessage.headerValues("From", in: Data(message.utf8)), ["a@example.com", "b@example.com"])
    }

    // MARK: - Removing a header

    func testRemovingHeader_dropsItAndItsContinuationAndLeavesTheRestAsIs() {
        let message = "From: alice@example.com\r\nX-MailGPG-SessionID: 1234\r\n 5678\r\nSubject: Hi\r\n\r\n"
            + "x-mailgpg-sessionid: in the body\r\n"
        let result = RawMessage.removingHeader("x-mailgpg-sessionid", from: Data(message.utf8))
        XCTAssertEqual(String(data: result, encoding: .utf8),
                       "From: alice@example.com\r\nSubject: Hi\r\n\r\nx-mailgpg-sessionid: in the body\r\n")
    }

    func testRemovingHeader_LFAndLastHeader() {
        let message = "From: alice@example.com\nX-MailGPG-SessionID: 1234\n\nHi"
        let result = RawMessage.removingHeader("X-MailGPG-SessionID", from: Data(message.utf8))
        XCTAssertEqual(String(data: result, encoding: .utf8), "From: alice@example.com\n\nHi")
    }

    func testRemovingHeader_absentHeaderLeavesTheBytesUnchanged() {
        let message = Data("From: alice@example.com\r\nX-MailGPG-Sign: yes\r\n\r\n\u{FF}".utf8)
        XCTAssertEqual(RawMessage.removingHeader("x-mailgpg-sessionid", from: message), message)
    }
}
