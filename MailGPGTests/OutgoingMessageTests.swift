// OutgoingMessageTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class OutgoingMessageTests: XCTestCase {

    private typealias Recipients = OutgoingMessage.Recipients

    private func recipients(visible: [String], blind: [String] = [],
                            status: [String: RecipientKeyStatus]?,
                            fingerprints: [String: String] = [:]) -> Result<Recipients, OutgoingMessage.RecipientProblem> {
        OutgoingMessage.recipients(visible: visible, blind: blind, status: status, fingerprints: fingerprints)
    }

    // MARK: - Missing message data

    func testMissingDataFailsSignOnly() {
        let errors = OutgoingMessage.missingDataErrors(shouldSign: true, shouldEncrypt: false)
        XCTAssertEqual(errors.signing?.code, 6)
        XCTAssertNil(errors.encryption)
    }

    func testMissingDataFailsEncryptOnly() {
        let errors = OutgoingMessage.missingDataErrors(shouldSign: false, shouldEncrypt: true)
        XCTAssertNil(errors.signing)
        XCTAssertEqual(errors.encryption?.code, 6)
    }

    func testMissingDataFailsSignAndEncrypt() {
        let errors = OutgoingMessage.missingDataErrors(shouldSign: true, shouldEncrypt: true)
        XCTAssertEqual(errors.signing?.code, 6)
        XCTAssertEqual(errors.encryption?.code, 6)
    }

    // MARK: - Recipients

    func testEveryRecipientWithAKeyIsEncryptedTo() {
        let result = recipients(visible: ["a@x", "b@x"], blind: ["c@x"],
                                status: ["a@x": .found, "b@x": .found, "c@x": .found],
                                fingerprints: ["a@x": "FA", "b@x": "FB", "c@x": "FC"])
        XCTAssertEqual(result, .success(Recipients(visible: ["FA", "FB"], hidden: ["FC"])))
    }

    /// Added after the last annotation run: it has no status entry yet.
    func testRecipientWithoutStatusIsRefused() {
        let result = recipients(visible: ["a@x", "new@x"], status: ["a@x": .found],
                                fingerprints: ["a@x": "FA"])
        XCTAssertEqual(result, .failure(.stillLoading(["new@x"])))
    }

    func testBlindRecipientWithoutStatusIsRefused() {
        let result = recipients(visible: ["a@x"], blind: ["new@x"], status: ["a@x": .found],
                                fingerprints: ["a@x": "FA"])
        XCTAssertEqual(result, .failure(.stillLoading(["new@x"])))
    }

    /// Send Later, a closed window, or no session header: nothing to go by.
    func testNoComposeStateIsRefused() {
        XCTAssertEqual(recipients(visible: ["a@x"], status: nil), .failure(.noComposeState))
    }

    func testNoRecipientsNeedsNoState() {
        XCTAssertEqual(recipients(visible: [""], status: nil), .success(Recipients()))
    }

    func testFoundStatusWithoutKeyIsMissing() {
        let result = recipients(visible: ["a@x"], status: ["a@x": .found])
        XCTAssertEqual(result, .failure(.missingKeys(["a@x"])))
    }

    func testProblemsAreReportedInOrderOfSeverity() {
        let status: [String: RecipientKeyStatus] = ["a@x": .loading, "b@x": .notFound, "c@x": .keyChanged]
        let fingerprints = ["c@x": "FC"]
        XCTAssertEqual(recipients(visible: ["a@x", "b@x", "c@x"], status: status, fingerprints: fingerprints),
                       .failure(.keyChanged(["c@x"])))
        XCTAssertEqual(recipients(visible: ["a@x", "b@x"], status: status), .failure(.missingKeys(["b@x"])))
        XCTAssertEqual(recipients(visible: ["a@x"], status: status), .failure(.stillLoading(["a@x"])))
    }

    func testKeyServingVisibleAndBlindAddressStaysVisible() {
        let result = recipients(visible: ["a@x", "a@x"], blind: ["alias@x", "a@x"],
                                status: ["a@x": .found, "alias@x": .found],
                                fingerprints: ["a@x": "FA", "alias@x": "FA"])
        XCTAssertEqual(result, .success(Recipients(visible: ["FA"], hidden: [])))
    }

    // MARK: - Cache key

    private let message = Data("From: me@x\r\nTo: a@x\r\nSubject: Hi\r\nDate: Mon, 1 Jan 2026\r\n\r\nBody\r\n".utf8)

    private func key(uuid: String? = "U1", sign: Bool = true, encrypt: Bool = true,
                     addresses: [String] = ["a@x"], recipients: Recipients = Recipients(visible: ["FA"]),
                     rawData: Data? = nil) -> String? {
        OutgoingMessage.cacheKey(messageUUID: uuid, shouldSign: sign, shouldEncrypt: encrypt,
                                 addresses: addresses, recipients: recipients, rawData: rawData ?? message)
    }

    func testNoUUIDIsNotCached() {
        XCTAssertNil(key(uuid: nil))
    }

    func testSameMessageSameKey() {
        XCTAssertEqual(key(), key())
    }

    func testVolatileHeadersDoNotChangeTheKey() {
        let resent = Data(("From: me@x\r\nTo: a@x\r\nSubject: Hi\r\nDate: Tue, 2 Jan 2026\r\n"
                         + "Message-Id: <other@x>\r\nX-Apple-Base-Url: x\r\n\r\nBody\r\n").utf8)
        XCTAssertEqual(key(), key(rawData: resent))
    }

    func testEditedBodyChangesTheKey() {
        let edited = Data("From: me@x\r\nTo: a@x\r\nSubject: Hi\r\nDate: Mon, 1 Jan 2026\r\n\r\nBody, edited\r\n".utf8)
        XCTAssertNotEqual(key(), key(rawData: edited))
    }

    func testEditedSubjectChangesTheKey() {
        let edited = Data("From: me@x\r\nTo: a@x\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2026\r\n\r\nBody\r\n".utf8)
        XCTAssertNotEqual(key(), key(rawData: edited))
    }

    func testAddedRecipientChangesTheKey() {
        XCTAssertNotEqual(key(), key(addresses: ["a@x", "bcc:b@x"],
                                     recipients: Recipients(visible: ["FA"], hidden: ["FB"])))
    }

    func testChangedKeyChangesTheKey() {
        XCTAssertNotEqual(key(), key(recipients: Recipients(visible: ["FA2"])))
    }

    func testToggledFlagsChangeTheKey() {
        XCTAssertNotEqual(key(), key(encrypt: false))
        XCTAssertNotEqual(key(), key(sign: false))
    }

    func testMessageWithoutHeaderEndHashesEverything() {
        let head = String(repeating: "X-Filler: y\r\n", count: 400)
        XCTAssertNotEqual(OutgoingMessage.contentDigest(Data((head + "a").utf8)),
                          OutgoingMessage.contentDigest(Data((head + "b").utf8)))
    }
}
