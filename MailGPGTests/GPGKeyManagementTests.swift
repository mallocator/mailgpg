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

    // MARK: - Autocrypt import

    private func importAutocrypt(_ keyData: Data, addr: String) -> (KeyInfo?, Error?) {
        wait { done in
            svc.importAutocryptKey(keyData: keyData, addr: addr) { data, error in
                done((data.flatMap { try? xpcDecode(KeyInfo.self, from: $0) }, error))
            }
        }
    }

    /// The colon-listing records of `kind` (pub, uid, fpr, …) for `keys`.
    private func records(_ kind: String, _ keys: [String] = []) throws -> [Substring] {
        let (out, _, _) = try homedir.run(["--list-keys", "--with-colons"] + keys)
        return try XCTUnwrap(String(data: out, encoding: .utf8)).split(separator: "\n")
            .filter { $0.hasPrefix(kind + ":") }
    }

    private func publicKeyCount() throws -> Int {
        try records("pub").count
    }

    /// An unprotected secret key with the user's own address would become the
    /// signing key on the next send.
    func testAutocryptImportRejectsSecretKey() throws {
        let (secret, _, code) = try homedir.run(["--export-secret-keys", homedir.fingerprint])
        XCTAssertEqual(code, 0)
        let fp = homedir.fingerprint
        _ = try homedir.run(["--batch", "--yes", "--delete-secret-and-public-key", fp])

        let (key, error) = importAutocrypt(secret, addr: homedir.email)
        XCTAssertNil(key)
        XCTAssertNotNil(error)
        XCTAssertEqual(try publicKeyCount(), 0, "Nothing may be imported")
        let (secrets, _, _) = try homedir.run(["--list-secret-keys", "--with-colons"])
        XCTAssertTrue(secrets.isEmpty, "No secret key may be imported")
    }

    func testAutocryptImportRejectsTwoKeys() throws {
        let (_, genErr, genCode) = try homedir.run(
            ["--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-gen-key", "Other <other@example.com>", "ed25519", "sign", "0"])
        XCTAssertEqual(genCode, 0, "Key generation failed: \(genErr)")
        let otherFP = try XCTUnwrap(records("fpr", ["other@example.com"]).first?
            .split(separator: ":", omittingEmptySubsequences: false)[9])
        let (both, _, _) = try homedir.run(["--export", homedir.fingerprint, String(otherFP)])
        _ = try homedir.run(["--batch", "--yes", "--delete-secret-and-public-key", String(otherFP)])

        let (key, error) = importAutocrypt(both, addr: homedir.email)
        XCTAssertNil(key)
        XCTAssertNotNil(error)
        XCTAssertEqual(try publicKeyCount(), 1, "The second key may not be imported")
    }

    /// A user ID for someone else would let the sender sign mail as them.
    func testAutocryptImportKeepsOnlySenderUID() throws {
        let fp = homedir.fingerprint
        let (_, uidErr, uidCode) = try homedir.run(
            ["--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-add-uid", fp, "Bank <alice@bank.example>"])
        XCTAssertEqual(uidCode, 0, "Adding a UID failed: \(uidErr)")
        let (keyData, _, _) = try homedir.run(["--export", fp])
        _ = try homedir.run(["--batch", "--yes", "--delete-secret-and-public-key", fp])

        let (key, error) = importAutocrypt(keyData, addr: homedir.email.uppercased())
        XCTAssertNil(error, "Import error: \(String(describing: error))")
        XCTAssertEqual(key?.fingerprint, fp)

        let uids = try records("uid", [fp])
        XCTAssertEqual(uids.count, 1)
        XCTAssertTrue(uids.first?.contains(homedir.email) ?? false)
    }

    func testAutocryptImportRejectsKeyWithoutSenderUID() throws {
        let fp = homedir.fingerprint
        let (keyData, _, _) = try homedir.run(["--export", fp])
        _ = try homedir.run(["--batch", "--yes", "--delete-secret-and-public-key", fp])

        let (key, error) = importAutocrypt(keyData, addr: "someone@example.com")
        XCTAssertNil(key)
        XCTAssertNotNil(error)
        XCTAssertEqual(try publicKeyCount(), 0)
    }

    func testAutocryptImportRejectsAddressThatBreaksFilter() throws {
        let (keyData, _, _) = try homedir.run(["--export", homedir.fingerprint])
        let (_, error) = importAutocrypt(keyData, addr: "a@x.example || mbox =~ @")
        assertEncodingFailed(error)
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

    // MARK: - Pinned key among several for one address

    /// Two keys carrying alice@bank.example, in listing order; Alice's pinned
    /// key is the second.
    private func twoKeysForAlice() throws -> (listing: [KeyInfo], other: KeyInfo, pinned: KeyInfo) {
        try addKey(uid: "Mallory <alice@bank.example>")
        try addKey(uid: "Alice <alice@bank.example>")
        let listing = try localListing("alice@bank.example")
        XCTAssertEqual(listing.count, 2)
        return (listing, listing[0], listing[1])
    }

    func testUsableKey_prefersPinnedKeyListedSecond() throws {
        let (listing, other, pinned) = try twoKeysForAlice()
        XCTAssertEqual(svc.usableKey(for: "alice@bank.example", in: listing, pinned: pinned.fingerprint)?.fingerprint,
                       pinned.fingerprint)
        XCTAssertEqual(svc.usableKey(for: "alice@bank.example", in: listing)?.fingerprint, other.fingerprint)
    }

    func testResolveKey_prefersPinnedKey() throws {
        let (_, _, pinned) = try twoKeysForAlice()
        let svc = GPGServiceImpl(gnupgHome: homedir.path, pinnedKeys: ["alice@bank.example": pinned.fingerprint])
        XCTAssertEqual(try svc.resolveKey(email: "Alice@Bank.example")?.fingerprint, pinned.fingerprint)
    }

    func testKeysByAddress_prefersPinnedKeyListedSecond() throws {
        let (listing, other, pinned) = try twoKeysForAlice()
        let byPin = KeyInfo.keysByAddress(listing) { $0 == "alice@bank.example" ? pinned.fingerprint : nil }
        XCTAssertEqual(byPin["alice@bank.example"]?.fingerprint, pinned.fingerprint)
        // No pin, or one for a key no longer in the keyring: the first listed, as before.
        let gone = String(repeating: "A", count: 40)
        for pin in [nil, gone] {
            let chosen = KeyInfo.keysByAddress(listing) { _ in pin }
            XCTAssertEqual(chosen["alice@bank.example"]?.fingerprint, other.fingerprint)
        }
    }
}
