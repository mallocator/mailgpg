// GPGKeyManagementTests.swift
// MailGPGTests – integration tests for key management operations.

import XCTest
@testable import MailGPG

final class GPGKeyManagementTests: XCTestCase {

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

    // MARK: - Semaphore helper

    /// Synchronously call a callback-based method and return its result.
    /// `block` receives a completion handler; call it to unblock and return the value.
    func wait<T>(_ block: (@escaping (T) -> Void) -> Void) -> T {
        var result: T!
        let sem = DispatchSemaphore(value: 0)
        block { value in result = value; sem.signal() }
        sem.wait()
        return result
    }

    private func assertEncodingFailed(
        _ error: Error?,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let error else {
            XCTFail("Expected encodingFailed error", file: file, line: line)
            return
        }
        let nsError = error as NSError
        XCTAssertEqual(nsError.domain, GPGXPCErrorDomain, file: file, line: line)
        XCTAssertEqual(nsError.code, GPGXPCError.encodingFailed.rawValue, file: file, line: line)
    }

    // MARK: - List keys

    func testListSecretKeys() throws {
        let sem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listSecretKeys { data, error in
            XCTAssertNil(error)
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let k = try XCTUnwrap(keys)
        XCTAssertEqual(k.count, 1)
        XCTAssertEqual(k[0].fingerprint, homedir.fingerprint)
        XCTAssertEqual(k[0].email, homedir.email)
        XCTAssertTrue(k[0].hasSecretKey)
    }

    func testListPublicKeys() throws {
        let sem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, error in
            XCTAssertNil(error)
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let k = try XCTUnwrap(keys)
        XCTAssertEqual(k.count, 1)
        XCTAssertEqual(k[0].fingerprint, homedir.fingerprint)
        XCTAssertFalse(k[0].isRevoked)
        // listPublicKeys passes wantSecretKeys:false — hasSecretKey must be false
        XCTAssertFalse(k[0].hasSecretKey)
    }

    // MARK: - Import / Export

    func testImportExportedPublicKey() throws {
        let fp = homedir.fingerprint

        // Export the public key armor
        let (armorData, exportErr, exportCode) = try homedir.run(["--export", "--armor", fp])
        XCTAssertEqual(exportCode, 0, "Export failed: \(exportErr)")
        let armor = try XCTUnwrap(String(data: armorData, encoding: .utf8))
        XCTAssertTrue(armor.contains("BEGIN PGP PUBLIC KEY BLOCK"))

        // Delete the secret key first (required before deleting the public key)
        let (_, _, delSecCode) = try homedir.run(["--batch", "--yes", "--delete-secret-key", fp])
        XCTAssertEqual(delSecCode, 0, "delete-secret-key failed")
        let (_, _, delPubCode) = try homedir.run(["--batch", "--yes", "--delete-key", fp])
        XCTAssertEqual(delPubCode, 0, "delete-key failed")

        // Re-import via GPGServiceImpl
        let sem = DispatchSemaphore(value: 0)
        var imported: KeyInfo?
        svc.importKey(armoredKey: armor) { data, error in
            XCTAssertNil(error, "Import error: \(String(describing: error))")
            imported = data.flatMap { try? xpcDecode(KeyInfo.self, from: $0) }
            sem.signal()
        }
        sem.wait()

        let key = try XCTUnwrap(imported)
        XCTAssertEqual(key.fingerprint, fp)
        XCTAssertEqual(key.email, homedir.email)
        XCTAssertFalse(key.hasSecretKey, "Re-imported public-only key must not have secret key")
    }

    // MARK: - Delete

    func testDeletePublicKey() throws {
        let fp = homedir.fingerprint

        // Must delete secret key before the public key
        let (_, _, _) = try homedir.run(["--batch", "--yes", "--delete-secret-key", fp])

        let sem = DispatchSemaphore(value: 0)
        var deleteError: Error?
        svc.deleteKey(fingerprint: fp) { error in
            deleteError = error
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(deleteError, "deleteKey returned error: \(String(describing: deleteError))")

        // Confirm the key is gone
        let listSem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, _ in
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            listSem.signal()
        }
        listSem.wait()
        XCTAssertEqual(keys?.count ?? -1, 0, "Key should have been deleted")
    }

    func testDeleteKeyRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.deleteKey(fingerprint: "DEADBEEF\nAABBCCDD112233441122334411223344AABBCCDD") { done($0) }
        }
        assertEncodingFailed(error)
    }

    // MARK: - Trust

    func testSetTrustLevel() throws {
        let fp = homedir.fingerprint

        let sem = DispatchSemaphore(value: 0)
        var setError: Error?
        svc.setTrust(fingerprint: fp, level: TrustLevel.full.rawValue) { error in
            setError = error
            sem.signal()
        }
        sem.wait()
        XCTAssertNil(setError, "setTrust returned error: \(String(describing: setError))")

        // Verify the trust level is reflected in the key listing
        let listSem = DispatchSemaphore(value: 0)
        var keys: [KeyInfo]?
        svc.listPublicKeys { data, _ in
            keys = data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) }
            listSem.signal()
        }
        listSem.wait()

        let key = try XCTUnwrap(keys?.first)
        XCTAssertEqual(key.trustLevel, .full, "Trust level should be .full after setTrust")
    }

    func testSetTrustRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.setTrust(fingerprint: "DEADBEEF\nAABBCCDD112233441122334411223344AABBCCDD",
                         level: TrustLevel.full.rawValue) { done($0) }
        }
        assertEncodingFailed(error)
    }

    // MARK: - Local sign (lsign)

    func testLsignKey() throws {
        let fp = homedir.fingerprint

        // lsignKey creates a local (non-exportable) signature on the key —
        // it's the mechanism users use to mark a key as "trusted for this machine".
        let (error) = wait { done in svc.lsignKey(fingerprint: fp) { done($0) } }
        XCTAssertNil(error, "lsignKey returned error: \(String(describing: error))")

        // After lsigning our own key the validity should advance to at least .full
        // (GPG considers a key valid when it has enough trusted signatures).
        let keys = wait { done in
            svc.listPublicKeys { data, _ in
                done(data.flatMap { try? xpcDecode([KeyInfo].self, from: $0) } ?? [])
            }
        }
        let key = try XCTUnwrap(keys.first)
        // A local signature by an ultimately-trusted key (our own) makes validity full.
        XCTAssertTrue(
            key.validity == .full || key.validity == .ultimate,
            "Expected validity .full or .ultimate after lsign, got \(key.validity)")
    }

    func testLsignKeyRejectsInvalidFingerprint() {
        let error = wait { done in
            svc.lsignKey(fingerprint: "--batch") { done($0) }
        }
        assertEncodingFailed(error)
    }

    // MARK: - Resolve by address

    /// Add a key with the single user ID `uid` to the test homedir.
    private func addKey(uid: String) throws {
        let (_, stderr, code) = try homedir.run(
            ["--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-gen-key", uid, "ed25519", "sign", "never"])
        XCTAssertEqual(code, 0, "Key generation failed: \(stderr)")
    }

    /// What step 1 of `resolveKey` gets from gpg when it searches for `email`.
    private func localListing(_ email: String) throws -> [KeyInfo] {
        let (out, _, _) = try homedir.run(["--list-keys", "--with-colons", "--fixed-list-mode", email])
        return svc.parseColonOutput(String(data: out, encoding: .utf8) ?? "", wantSecretKeys: false)
    }

    func testUsableKey_ignoresSubstringMatch() throws {
        // gpg matches a bare address as a substring of the user ID, so its
        // listing for bob holds Mallory's key.
        try addKey(uid: "Mallory <notbob@example.com>")
        let listing = try localListing("bob@example.com")
        XCTAssertEqual(listing.map(\.emails), [["notbob@example.com"]])
        XCTAssertNil(svc.usableKey(for: "bob@example.com", in: listing))
    }

    func testUsableKey_picksTheKeyCarryingTheAddress() throws {
        try addKey(uid: "Mallory <notbob@example.com>")
        try addKey(uid: "Bob <bob@example.com>")
        let key = svc.usableKey(for: "Bob@Example.com", in: try localListing("bob@example.com"))
        XCTAssertEqual(key?.emails, ["bob@example.com"])
    }

    func testResolveKey_findsBareAddressKeyLocally() throws {
        try addKey(uid: "bare@example.com")
        let key = try svc.resolveKey(email: "bare@example.com")
        XCTAssertEqual(key?.email, "bare@example.com")
    }

    func testResolveKey_addressCannotInjectGPGOptions() throws {
        // gpg reads options after operands too, and `--log-file=/path/x@y`
        // is a valid address, e.g. a From header of an incoming mail.
        let logPath = homedir.path + "/injected@example.com"
        let key = try svc.resolveKey(email: "--log-file=\(logPath)")
        XCTAssertNil(key)
        XCTAssertFalse(FileManager.default.fileExists(atPath: logPath), "gpg took the address as an option")
    }

    func testUsableKey_forEncryptionSkipsSignOnlyKey() throws {
        // A key whose encryption subkey is gone or expired lists fine but
        // makes gpg refuse to encrypt.
        try addKey(uid: "Signer <signer@example.com>")
        let listing = try localListing("signer@example.com")
        XCTAssertNotNil(svc.usableKey(for: "signer@example.com", in: listing))
        XCTAssertNil(svc.usableKey(for: "signer@example.com", in: listing, forEncryption: true))
        XCTAssertNotNil(svc.usableKey(for: homedir.email, in: try localListing(homedir.email), forEncryption: true))
    }
}
