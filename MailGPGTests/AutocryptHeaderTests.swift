// AutocryptHeaderTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class AutocryptHeaderTests: XCTestCase {

    /// A short stand-in for a transferable public key. The parser does not care
    /// what the bytes are, only that they decode.
    private let keyBytes = Data([0x99, 0x01, 0x0d, 0x04, 0xde, 0xad, 0xbe, 0xef])
    private var keydata: String { keyBytes.base64EncodedString() }

    func testParsesAddrAndKeydata() {
        let parsed = AutocryptHeader.parse("addr=alice@example.com; keydata=\(keydata)")
        XCTAssertEqual(parsed?.addr, "alice@example.com")
        XCTAssertEqual(parsed?.keyData, keyBytes)
    }

    func testAddrIsLowercased() {
        // Addresses are compared against the From header, which we lowercase too.
        let parsed = AutocryptHeader.parse("addr=Alice@Example.COM; keydata=\(keydata)")
        XCTAssertEqual(parsed?.addr, "alice@example.com")
    }

    func testPreferEncryptIsAccepted() {
        let parsed = AutocryptHeader.parse(
            "addr=alice@example.com; prefer-encrypt=mutual; keydata=\(keydata)")
        XCTAssertEqual(parsed?.keyData, keyBytes)
    }

    func testFoldedKeydataIsReassembled() {
        // Real headers are folded — CRLF plus a space — because the base64 of a
        // key runs past RFC 5322's 998-octet line limit.
        let folded = keydata.prefix(4) + "\r\n " + keydata.dropFirst(4)
        let parsed = AutocryptHeader.parse("addr=alice@example.com;\r\n keydata=\(folded)")
        XCTAssertEqual(parsed?.keyData, keyBytes)
    }

    func testUnderscoreAttributesAreIgnored() {
        let parsed = AutocryptHeader.parse(
            "addr=alice@example.com; _experimental=whatever; keydata=\(keydata)")
        XCTAssertEqual(parsed?.keyData, keyBytes)
    }

    func testUnknownCriticalAttributeRejectsTheHeader() {
        // Spec: an unrecognised attribute without an underscore prefix means the
        // header must be discarded, because it may change what the rest means.
        XCTAssertNil(AutocryptHeader.parse(
            "addr=alice@example.com; mustunderstand=1; keydata=\(keydata)"))
    }

    func testMissingAddrIsRejected() {
        XCTAssertNil(AutocryptHeader.parse("keydata=\(keydata)"))
    }

    func testMissingKeydataIsRejected() {
        XCTAssertNil(AutocryptHeader.parse("addr=alice@example.com"))
    }

    func testEmptyKeydataIsRejected() {
        XCTAssertNil(AutocryptHeader.parse("addr=alice@example.com; keydata="))
    }

    func testGarbageKeydataIsRejected() {
        XCTAssertNil(AutocryptHeader.parse("addr=alice@example.com; keydata=!!!!"))
    }

    func testEmptyHeaderIsRejected() {
        XCTAssertNil(AutocryptHeader.parse(""))
    }
}
