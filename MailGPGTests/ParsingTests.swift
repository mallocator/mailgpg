// ParsingTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

final class ParsingTests: XCTestCase {

    let svc = GPGServiceImpl()

    // MARK: - parseUID

    func testParseUID_fullFormat() {
        let (name, email) = svc.parseUID("Alice Wonderland (work key) <alice@example.com>")
        XCTAssertEqual(name,  "Alice Wonderland")
        XCTAssertEqual(email, "alice@example.com")
    }

    func testParseUID_noComment() {
        let (name, email) = svc.parseUID("Bob Builder <bob@example.com>")
        XCTAssertEqual(name,  "Bob Builder")
        XCTAssertEqual(email, "bob@example.com")
    }

    func testParseUID_noEmail() {
        let (name, email) = svc.parseUID("Carol Without Email")
        XCTAssertEqual(name,  "Carol Without Email")
        XCTAssertEqual(email, "")
    }

    func testParseUID_emailOnly() {
        let (_, email) = svc.parseUID("<dave@example.com>")
        XCTAssertEqual(email, "dave@example.com")
    }

    func testParseUID_empty() {
        let (name, email) = svc.parseUID("")
        XCTAssertEqual(name,  "")
        XCTAssertEqual(email, "")
    }

    func testParseUID_usesLastAngleBrackets() {
        // Multiple angle bracket pairs → last pair wins
        let (_, email) = svc.parseUID("Name <old@example.com> <real@example.com>")
        XCTAssertEqual(email, "real@example.com")
    }

    // MARK: - parseColonOutput: public keys

    // GPG colon format: type:validity:keylen:algo:keyid:created:expires:hash:ownertrust:uid_or_fpr...
    //                    [0]    [1]      [2]   [3]   [4]    [5]     [6]   [7]    [8]       [9]

    func testParseColonOutput_publicKey() {
        // validity(f=full), ownertrust(u=ultimate), no expiry
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Alice Wonderland <alice@example.com>:::::::::0:
            sub:f:4096:1:DEADBEEFDEADBEEF:1600000000::::::e:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        let k = keys[0]
        XCTAssertEqual(k.fingerprint,  "AABBCCDD112233441122334411223344AABBCCDD")
        XCTAssertEqual(k.keyID,        "AABBCCDD")    // last 8 chars of fingerprint
        XCTAssertEqual(k.name,         "Alice Wonderland")
        XCTAssertEqual(k.email,        "alice@example.com")
        XCTAssertEqual(k.trustLevel,   .ultimate)     // ownertrust field = 'u'
        XCTAssertEqual(k.validity,     .full)          // validity field   = 'f'
        XCTAssertFalse(k.hasSecretKey)
        XCTAssertFalse(k.isRevoked)
        XCTAssertNil(k.expiresAt)
    }

    func testParseColonOutput_secretKey() {
        let output = """
            sec:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Bob Builder <bob@example.com>:::::::::0:
            ssb:u:4096:1:DEADBEEFDEADBEEF:1600000000::::::e:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: true)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].name,  "Bob Builder")
        XCTAssertEqual(keys[0].email, "bob@example.com")
        XCTAssertTrue(keys[0].hasSecretKey)
    }

    func testParseColonOutput_secretKeyStub() {
        // sec# = stub: key lives on smartcard/YubiKey, no local private key bytes
        let output = """
            sec#:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Carol Yubikey <carol@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: true)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].email, "carol@example.com")
    }

    func testParseColonOutput_revokedKey() {
        let output = """
            pub:r:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:r::::1600000001::UID_HASH::Dave Revoked <dave@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertTrue(keys[0].isRevoked)
    }

    func testParseColonOutput_withExpiry() {
        let expiry: Double = 1893456000
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:\(Int(expiry))::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Eve Expires <eve@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertNotNil(keys[0].expiresAt)
        XCTAssertEqual(keys[0].expiresAt!.timeIntervalSince1970, expiry, accuracy: 1.0)
    }

    func testParseColonOutput_ownertrust_n_mapsToNone() {
        // GPG uses 'n' for "not trusted" in the ownertrust field, but 'n' is not a
        // TrustLevel raw value — it must be explicitly mapped to .none.
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::n:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Frank <frank@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].trustLevel, .none)
    }

    func testParseColonOutput_validity_n_mapsToNone() {
        // Same mapping but for the validity field
        let output = """
            pub:n:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:n::::1600000001::UID_HASH::Grace <grace@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].validity, .none)
    }

    func testParseColonOutput_firstUIDOnly() {
        // Multiple UIDs per key — only the first should be returned
        let output = """
            pub:f:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:f::::1600000001::UID_HASH::Primary Name <primary@example.com>:::::::::0:
            uid:f::::1600000002::UID_HASH::Secondary Name <secondary@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].email, "primary@example.com")
    }

    func testParseColonOutput_ignoresSecKeyRecords_whenWantingPublic() {
        let output = """
            sec:u:4096:1:AABBCCDD11223344:1600000000:::u:
            fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
            uid:u::::1600000001::UID_HASH::Alice <alice@example.com>:::::::::0:
            """
        let keys = svc.parseColonOutput(output, wantSecretKeys: false)
        XCTAssertTrue(keys.isEmpty, "sec record must be ignored when wantSecretKeys=false")
    }

    func testParseColonOutput_multipleTrustLevels() {
        // Smoke-test all TrustLevel raw values round-trip through the parser
        let levels: [(String, TrustLevel)] = [("?", .unknown), ("-", .none), ("m", .marginal), ("f", .full), ("u", .ultimate)]
        for (raw, expected) in levels {
            let output = """
                pub:f:4096:1:AABBCCDD11223344:1600000000:::\(raw):
                fpr:::::::::AABBCCDD112233441122334411223344AABBCCDD:
                uid:f::::1600000001::H::Test <test@example.com>:::::::::0:
                """
            let keys = svc.parseColonOutput(output, wantSecretKeys: false)
            XCTAssertEqual(keys.first?.trustLevel, expected, "raw='\(raw)' should map to \(expected)")
        }
    }

    // MARK: - parseDecryptStatus

    func testParseDecryptStatus_encryptedOnly() {
        let stderr = """
            gpg: encrypted with rsa4096 key
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] DECRYPTION_OKAY
            """
        let status = svc.parseDecryptStatus(status: stderr)
        if case .encrypted(let signers) = status {
            XCTAssertTrue(signers.isEmpty)
        } else {
            XCTFail("Expected .encrypted, got \(status)")
        }
    }

    func testParseDecryptStatus_encryptedAndSigned() {
        // GOODSIG followed by VALIDSIG (which provides the full fingerprint)
        let stderr = """
            [GNUPG:] ENC_TO AABBCCDD11223344 1 0
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] GOODSIG AABBCCDD11223344 Alice Wonderland <alice@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200 0 4 0 1 8 00 AABBCCDD112233441122334411223344AABBCCDD
            """
        let status = svc.parseDecryptStatus(status: stderr)
        if case .encrypted(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email,       "alice@example.com")
            XCTAssertEqual(signers[0].keyID,       "AABBCCDD11223344")
            XCTAssertEqual(signers[0].fingerprint, "AABBCCDD112233441122334411223344AABBCCDD")
        } else {
            XCTFail("Expected .encrypted(signers:), got \(status)")
        }
    }

    func testParseDecryptStatus_signedOnly() {
        // GOODSIG without DECRYPTION_OKAY → signed but not encrypted
        let stderr = """
            [GNUPG:] GOODSIG AABBCCDD11223344 Bob <bob@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200
            """
        let status = svc.parseDecryptStatus(status: stderr)
        if case .signed(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email, "bob@example.com")
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseDecryptStatus_badSig() {
        let stderr = """
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] BADSIG AABBCCDD11223344 Eve Attacker
            """
        let status = svc.parseDecryptStatus(status: stderr)
        if case .signatureInvalid(let reason) = status {
            XCTAssert(reason.contains("AABBCCDD11223344"), "reason=\(reason)")
        } else {
            XCTFail("Expected .signatureInvalid, got \(status)")
        }
    }

    func testParseDecryptStatus_noPubKey() {
        let stderr = "[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF"
        let status = svc.parseDecryptStatus(status: stderr)
        if case .keyNotFound(let keyID) = status {
            XCTAssertEqual(keyID, "DEADBEEFDEADBEEF")
        } else {
            XCTFail("Expected .keyNotFound, got \(status)")
        }
    }

    func testParseDecryptStatus_plain() {
        let status = svc.parseDecryptStatus(status: "gpg: no encrypted data found")
        XCTAssertEqual(status, .plain)
    }

    // MARK: - parseVerifyStatus

    func testParseVerifyStatus_goodSig() {
        let stdout = """
            [GNUPG:] GOODSIG AABBCCDD11223344 Alice Wonderland <alice@example.com>
            [GNUPG:] VALIDSIG AABBCCDD112233441122334411223344AABBCCDD 2021-01-01 1609459200
            """
        let status = svc.parseVerifyStatus(status: stdout)
        if case .signed(let signers) = status {
            XCTAssertEqual(signers.count, 1)
            XCTAssertEqual(signers[0].email,       "alice@example.com")
            XCTAssertEqual(signers[0].keyID,       "AABBCCDD11223344")
            XCTAssertEqual(signers[0].fingerprint, "AABBCCDD112233441122334411223344AABBCCDD")
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseVerifyStatus_goodSig_noEmail_fallsBackToName() {
        // GOODSIG with a plain name (no <email>) → name is used as email field
        let stdout = "[GNUPG:] GOODSIG AABBCCDD11223344 Just A Name"
        let status = svc.parseVerifyStatus(status: stdout)
        if case .signed(let signers) = status {
            XCTAssertFalse(signers[0].email.isEmpty)
        } else {
            XCTFail("Expected .signed, got \(status)")
        }
    }

    func testParseVerifyStatus_badSig() {
        let stdout = "[GNUPG:] BADSIG AABBCCDD11223344 Eve Attacker"
        let status = svc.parseVerifyStatus(status: stdout)
        if case .signatureInvalid(_) = status { /* pass */ }
        else { XCTFail("Expected .signatureInvalid, got \(status)") }
    }

    func testParseVerifyStatus_noPubKey() {
        let stdout = "[GNUPG:] NO_PUBKEY DEADBEEFDEADBEEF"
        let status = svc.parseVerifyStatus(status: stdout)
        if case .keyNotFound(let keyID) = status {
            XCTAssertEqual(keyID, "DEADBEEFDEADBEEF")
        } else {
            XCTFail("Expected .keyNotFound, got \(status)")
        }
    }

    func testParseVerifyStatus_humanReadableTextIsNotTrusted() {
        // Text that looks like a successful verification but carries no
        // [GNUPG:] status line must NOT produce .signed. GPG echoes
        // attacker-chosen user IDs in its human-readable output, so the old
        // fallback was forgeable by anyone who could get a key imported.
        let status = svc.parseVerifyStatus(status: "gpg: Good signature from \"Alice\"")
        if case .signatureInvalid(_) = status { /* pass */ }
        else { XCTFail("Expected .signatureInvalid for non-status text, got \(status)") }
    }

    func testParseVerifyStatus_unknownFailure() {
        let status = svc.parseVerifyStatus(status: "gpg: something went wrong")
        if case .signatureInvalid(_) = status { /* pass */ }
        else { XCTFail("Expected .signatureInvalid for unrecognised output, got \(status)") }
    }

    // MARK: - multiple user IDs per key

    /// Real `gpg --list-keys --with-colons` output: four user IDs, one of them
    /// revoked, one containing an escaped colon. GPG lists the most recently
    /// added first, so "the first uid" is an arbitrary address.
    private let multiUIDKey = """
    pub:u:255:22:EF76E9E1C81672EB:1788167858:::u:::scaESCA:::::ed25519:::0:
    fpr:::::::::915EB0E99DC86EE8756FC795EF76E9E1C81672EB:
    uid:u::::1788294127::04717A2F::Old Address <old@example.com>::::::::::0:
    uid:r::::::73B14EB7::Alice\\x3a The Boss <colon@example.com>::::::::::0:
    uid:u::::1788167858::2BE3C731::Ravi Test <secondary@example.com>::::::::::0:
    uid:u::::1788167858::0A45B84F::Ravi Test <primary@example.com>::::::::::0:
    sub:u:255:18:AC58B30136D64701:1788167858::::::e:::::cv25519::
    """

    func testParseColonOutput_emitsOneKeyPerFingerprint() {
        // Several entries sharing a fingerprint would collide as Identifiable
        // rows in the key lists.
        let keys = svc.parseColonOutput(multiUIDKey, wantSecretKeys: false)
        XCTAssertEqual(keys.count, 1)
    }

    func testParseColonOutput_collectsEveryLiveAddress() {
        guard let key = svc.parseColonOutput(multiUIDKey, wantSecretKeys: false).first else {
            return XCTFail("Expected one key")
        }
        XCTAssertTrue(key.emails.contains("secondary@example.com"))
        XCTAssertTrue(key.emails.contains("primary@example.com"))
        XCTAssertTrue(key.emails.contains("old@example.com"))
    }

    func testParseColonOutput_excludesRevokedUserIDs() {
        // The owner retired that address. Encrypting to it must not keep
        // working just because the key as a whole is still valid.
        guard let key = svc.parseColonOutput(multiUIDKey, wantSecretKeys: false).first else {
            return XCTFail("Expected one key")
        }
        XCTAssertFalse(key.emails.contains("colon@example.com"))
    }

    func testUnescapeColonField_decodesEscapedColon() {
        XCTAssertEqual(svc.unescapeColonField("Alice\\x3a The Boss"), "Alice: The Boss")
        XCTAssertEqual(svc.unescapeColonField("back\\x5cslash"), "back\\slash")
        XCTAssertEqual(svc.unescapeColonField("nothing to do"), "nothing to do")
    }

    // MARK: - key creation date

    func testParseColonOutput_capturesCreationDate() {
        // Colon field 6 is the creation date as a Unix timestamp.
        // 1300000000 = 2011-03-13.
        let out = """
        pub:u:255:22:AAAABBBBCCCCDDDD:1300000000::::::scESC::::::23::0:
        fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBCCCC:
        uid:u::::1300000000::ABC::Alice <alice@example.com>::::::::::0:
        """
        guard let key = svc.parseColonOutput(out, wantSecretKeys: false).first else {
            return XCTFail("Expected one key")
        }
        XCTAssertEqual(key.createdAt, Date(timeIntervalSince1970: 1300000000))
        XCTAssertNil(key.expiresAt, "No expiry field set, so expiresAt should be nil")
    }

    // MARK: - status output captured from real GPG

    /// These are verbatim from gpg 2.x, not hand-written approximations. Two
    /// details only show up in the real thing: a user ID can be a bare address
    /// with no angle brackets, and gpg exits 0 for a signature made by a
    /// revoked or expired key — so the status lines are the only signal.

    func testRealGPG_goodSignature() {
        let status = """
        [GNUPG:] NEWSIG
        [GNUPG:] KEY_CONSIDERED 1538E321447B19EEBF11D6BAAA1E0D9C2414CED7 0
        [GNUPG:] SIG_ID sTaSvLEu7ixrkUpDM39iA650AYc 2026-09-01 1788294359
        [GNUPG:] GOODSIG AA1E0D9C2414CED7 sig@example.com
        [GNUPG:] VALIDSIG 1538E321447B19EEBF11D6BAAA1E0D9C2414CED7 2026-09-01 1788294359 0 4 0 22 10 00 1538E321447B19EEBF11D6BAAA1E0D9C2414CED7
        [GNUPG:] TRUST_ULTIMATE 0 pgp
        """
        guard case .signed(let signers) = svc.parseVerifyStatus(status: status) else {
            return XCTFail("Expected .signed")
        }
        XCTAssertEqual(signers.first?.keyID, "AA1E0D9C2414CED7")
        // A bare address with no angle brackets is a valid user ID.
        XCTAssertEqual(signers.first?.email, "sig@example.com")
        // VALIDSIG carries the full fingerprint; the short key ID is not enough.
        XCTAssertEqual(signers.first?.fingerprint,
                       "1538E321447B19EEBF11D6BAAA1E0D9C2414CED7")
    }

    func testRealGPG_badSignature() {
        let status = """
        [GNUPG:] NEWSIG
        [GNUPG:] KEY_CONSIDERED 1538E321447B19EEBF11D6BAAA1E0D9C2414CED7 0
        [GNUPG:] BADSIG AA1E0D9C2414CED7 sig@example.com
        [GNUPG:] FAILURE gpg-exit 33554433
        """
        guard case .signatureInvalid = svc.parseVerifyStatus(status: status) else {
            return XCTFail("Expected .signatureInvalid")
        }
    }

    func testRealGPG_revokedKeyEmitsNoGoodsig() {
        // gpg exits 0 here. Without reading REVKEYSIG this would look fine.
        let status = """
        [GNUPG:] REVKEYSIG 0E63A9F618BBC8B5 revoketest@example.com
        [GNUPG:] KEYREVOKED
        """
        guard case .signatureInvalid(let reason) = svc.parseVerifyStatus(status: status) else {
            return XCTFail("Expected .signatureInvalid for a revoked key")
        }
        XCTAssertTrue(reason.lowercased().contains("revoked"), "got: \(reason)")
    }

    func testRealGPG_expiredKeyEmitsNoGoodsig() {
        let status = """
        [GNUPG:] KEYEXPIRED 1788380856
        [GNUPG:] EXPKEYSIG 1F3B938459C92644 exp@example.com
        """
        guard case .signatureInvalid(let reason) = svc.parseVerifyStatus(status: status) else {
            return XCTFail("Expected .signatureInvalid for an expired key")
        }
        XCTAssertTrue(reason.lowercased().contains("expired"), "got: \(reason)")
    }

    func testRealGPG_decryptWithEmbeddedSignature() {
        // DECRYPTION_OKAY comes last, after the signature lines.
        let status = """
        [GNUPG:] ENC_TO 81A141E4D0CBF4C7 18 0
        [GNUPG:] GOODSIG 0B43915FAE5E1CC3 enc@example.com
        [GNUPG:] VALIDSIG 6EB70BE8A475354A3EB7F8620B43915FAE5E1CC3 2026-09-01 1788294456 0 4 0 22 10 00 6EB70BE8A475354A3EB7F8620B43915FAE5E1CC3
        [GNUPG:] DECRYPTION_OKAY
        """
        guard case .encrypted(let signers) = svc.parseDecryptStatus(status: status) else {
            return XCTFail("Expected .encrypted")
        }
        XCTAssertEqual(signers.first?.email, "enc@example.com")
        XCTAssertEqual(signers.first?.fingerprint,
                       "6EB70BE8A475354A3EB7F8620B43915FAE5E1CC3")
    }

    func testRealGPG_encryptedWithNoSignature() {
        let status = """
        [GNUPG:] ENC_TO 81A141E4D0CBF4C7 18 0
        [GNUPG:] DECRYPTION_OKAY
        """
        guard case .encrypted(let signers) = svc.parseDecryptStatus(status: status) else {
            return XCTFail("Expected .encrypted")
        }
        XCTAssertTrue(signers.isEmpty)
    }

    // MARK: - revoked / expired signing keys

    func testParseVerifyStatus_revokedKeyIsNotAValidSignature() {
        // GPG emits REVKEYSIG in place of GOODSIG. Without an explicit branch
        // this fell through to the generic "no valid signature", which hides
        // the much stronger fact that the owner revoked the key.
        let status = svc.parseVerifyStatus(
            status: "[GNUPG:] REVKEYSIG DEADBEEFDEADBEEF Alice <alice@example.com>")
        if case .signatureInvalid(let reason) = status {
            XCTAssertTrue(reason.lowercased().contains("revoked"), "got: \(reason)")
        } else {
            XCTFail("Expected .signatureInvalid for a revoked key, got \(status)")
        }
    }

    func testParseVerifyStatus_expiredKeyIsNotAValidSignature() {
        let status = svc.parseVerifyStatus(
            status: "[GNUPG:] EXPKEYSIG DEADBEEFDEADBEEF Alice <alice@example.com>")
        if case .signatureInvalid(let reason) = status {
            XCTAssertTrue(reason.lowercased().contains("expired"), "got: \(reason)")
        } else {
            XCTFail("Expected .signatureInvalid for an expired key, got \(status)")
        }
    }

    func testParseDecryptStatus_revokedSigningKeyInsideEncryptedMessage() {
        let status = svc.parseDecryptStatus(status: """
            [GNUPG:] DECRYPTION_OKAY
            [GNUPG:] REVKEYSIG DEADBEEFDEADBEEF Alice <alice@example.com>
            """)
        if case .signatureInvalid(let reason) = status {
            XCTAssertTrue(reason.lowercased().contains("revoked"), "got: \(reason)")
        } else {
            XCTFail("Expected .signatureInvalid for a revoked key, got \(status)")
        }
    }

    // MARK: - extractFromEmail

    func testExtractFromEmail_angleFormat() {
        let msg = "From: Alice Wonderland <alice@example.com>\nTo: bob@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    func testExtractFromEmail_plainEmail() {
        let msg = "From: alice@example.com\nTo: bob@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    func testExtractFromEmail_noFromHeader() {
        let msg = "To: bob@example.com\n\nHello"
        XCTAssertNil(svc.extractFromEmail(from: msg.data(using: .utf8)!))
    }

    func testExtractFromEmail_caseInsensitive() {
        let msg = "FROM: alice@example.com\n\nHello"
        XCTAssertEqual(svc.extractFromEmail(from: msg.data(using: .utf8)!), "alice@example.com")
    }

    // MARK: - parseImportedFingerprint

    func testParseImportedFingerprint_valid() {
        let output = """
            [GNUPG:] IMPORT_OK 1 AABBCCDD112233441122334411223344AABBCCDD
            [GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0
            """
        XCTAssertEqual(
            svc.parseImportedFingerprint(from: output),
            "AABBCCDD112233441122334411223344AABBCCDD"
        )
    }

    func testParseImportedFingerprint_notFound() {
        let output = "[GNUPG:] IMPORT_RES 0 0 0 0 0 0 0 0 0 0 0"
        XCTAssertNil(svc.parseImportedFingerprint(from: output))
    }

    func testParseImportedFingerprint_multipleImports_returnsFirst() {
        let output = """
            [GNUPG:] IMPORT_OK 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            [GNUPG:] IMPORT_OK 1 BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
            """
        XCTAssertEqual(
            svc.parseImportedFingerprint(from: output),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
    }
}
