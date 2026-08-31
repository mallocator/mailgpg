// GPGService.swift
// MailGPGExtension (extension only)

import Foundation

// MARK: - HostAppReachability

/// Thread-safe shared state tracking whether the GPG host app is reachable.
/// `nil` = not yet checked, `true` = confirmed, `false` = unreachable.
/// Updated by GPGService after ping attempts and connection changes;
/// read by MessageSecurityHandler to drive the compose button indicator.
final class HostAppReachability: @unchecked Sendable {
    static let shared = HostAppReachability()
    private let lock = NSLock()
    private var _isAvailable: Bool?
    private var _isChecking = false

    var isAvailable: Bool? {
        get { lock.lock(); defer { lock.unlock() }; return _isAvailable }
        set { lock.lock(); defer { lock.unlock() }; _isAvailable = newValue; _isChecking = false }
    }

    /// Atomically claim the "checking" slot. Returns `true` if this caller
    /// should perform the ping; `false` if another caller is already doing it.
    func beginCheckIfNeeded() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard _isAvailable == nil, !_isChecking else { return false }
        _isChecking = true
        return true
    }
}

// MARK: - GPGService

/// The public API surface for GPG operations inside the Mail extension.
///
/// All methods are `async throws` — callers just `await` them like any
/// other async Swift call. Internally this wraps the XPC callback protocol.
///
/// ## Usage
///     let signed = try await GPGService.shared.sign(data: body, signerKeyID: keyID)
actor GPGService {

    static let shared = GPGService()

    private let connection = GPGServiceConnection()

    private init() {
        // Seed default keyservers into the shared UserDefaults container so the
        // host app can read them without duplicating the list.
        if (Self.defaults?.stringArray(forKey: "keyservers") ?? []).isEmpty {
            Self.defaults?.set(Self.defaultKeyservers, forKey: "keyservers")
        }
        // Permanently wire connection availability changes to HostAppReachability.
        // true  = connect() called optimistically → nil (re-checking, not confirmed yet)
        // false = connection failed / host app quit → false (confirmed unavailable)
        connection.onAvailabilityChanged = { available in
            HostAppReachability.shared.isAvailable = available ? nil : false
        }
    }

    // MARK: - Diagnostics

    /// Calls the host app and returns its GPG version string.
    /// A successful result confirms the full XPC round-trip is working.
    func ping() async throws -> String {
        let proxy = try connection.proxy()

        // Save the existing availability callback so we can restore it after.
        let savedHandler = connection.onAvailabilityChanged

        // When XPC drops an in-flight reply block (connection invalidated before
        // the host app replies), withCheckedThrowingContinuation leaks its
        // continuation. Fix: hook into onAvailabilityChanged so that if the
        // connection dies before the reply arrives, we resume with an error.
        // OneShotRelay ensures only one resume regardless of which path fires first.
        let result = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            let relay = OneShotRelay(continuation)

            connection.onAvailabilityChanged = { [savedHandler] available in
                savedHandler?(available)
                if !available {
                    relay.resume(throwing: GPGXPCError.make(.hostAppNotRunning,
                        message: "MailGPG host app is not running. Please open it to enable GPG operations."))
                }
            }

            proxy.ping { version, error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: version ?? "(no version returned)")
            }
        }

        // Back on the actor's executor — restore the permanent handler and
        // mark the host app as confirmed available.
        connection.onAvailabilityChanged = savedHandler
        HostAppReachability.shared.isAvailable = true
        return result
    }

    /// Returns a full snapshot of the GPG environment on the host machine.
    func getSystemStatus() async throws -> SystemStatus {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.getSystemStatus { statusJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let statusJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed)); return
                }
                continuation.resume(with: statusJSON, as: SystemStatus.self)
            }
        }
    }

    /// Write `pinentry-mac` to `gpg-agent.conf` and restart the agent.
    func fixPinentry() async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.fixPinentry { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    // MARK: - Outgoing

    func sign(data: Data, signerKeyID: String) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.sign(data: data, signerKeyID: signerKeyID) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    func encrypt(data: Data, recipientFingerprints: [String],
                 hiddenRecipientFingerprints: [String] = []) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.encrypt(data: data,
                          recipientFingerprints: recipientFingerprints,
                          hiddenRecipientFingerprints: hiddenRecipientFingerprints) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    func signAndEncrypt(data: Data, signerKeyID: String,
                        recipientFingerprints: [String],
                        hiddenRecipientFingerprints: [String] = []) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.signAndEncrypt(data: data, signerKeyID: signerKeyID,
                                 recipientFingerprints: recipientFingerprints,
                                 hiddenRecipientFingerprints: hiddenRecipientFingerprints) { result, error in
                continuation.resume(with: result, error: error)
            }
        }
    }

    // MARK: - Incoming

    func decrypt(data: Data) async throws -> (plaintext: Data, status: SecurityStatus) {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.decrypt(data: data) { plaintextData, statusJSON, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                // Both values must be present on success.
                guard let plaintextData, let statusJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                do {
                    let status = try xpcDecode(SecurityStatus.self, from: statusJSON)
                    continuation.resume(returning: (plaintextData, status))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func verify(data: Data, signature: Data) async throws -> SecurityStatus {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.verify(data: data, signature: signature) { statusJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let statusJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                continuation.resume(with: statusJSON, as: SecurityStatus.self)
            }
        }
    }

    // MARK: - Key management

    func lookupKey(email: String) async throws -> KeyInfo? {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.lookupKey(email: email) { keyInfoJSON, error in
                if let error { continuation.resume(throwing: error); return }
                // nil data with no error means the key simply doesn't exist.
                guard let keyInfoJSON else {
                    continuation.resume(returning: Optional<KeyInfo>.none)
                    return
                }
                do {
                    continuation.resume(returning: try xpcDecode(KeyInfo.self, from: keyInfoJSON))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func listSecretKeys() async throws -> [KeyInfo] {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.listSecretKeys { keyListJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyListJSON else {
                    continuation.resume(returning: [])
                    return
                }
                continuation.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func importKey(armoredKey: String) async throws -> KeyInfo {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.importKey(armoredKey: armoredKey) { keyInfoJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyInfoJSON else {
                    continuation.resume(throwing: GPGXPCError.make(.encodingFailed))
                    return
                }
                continuation.resume(with: keyInfoJSON, as: KeyInfo.self)
            }
        }
    }

    func importKeyData(_ keyData: Data) async throws -> KeyInfo {
        let proxy = try connection.proxy()
        let json: Data = try await withCheckedThrowingContinuation { continuation in
            proxy.importKeyData(keyData: keyData) { data, error in
                continuation.resume(with: data, error: error)
            }
        }
        return try xpcDecode(KeyInfo.self, from: json)
    }

    func exportPublicKey(fingerprint: String) async throws -> Data {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.exportPublicKey(fingerprint: fingerprint) { data, error in
                continuation.resume(with: data, error: error)
            }
        }
    }

    // MARK: - Autocrypt

    /// Whether outgoing mail carries an Autocrypt header. Off by default.
    nonisolated func getAutocryptEnabled() -> Bool {
        Self.defaults?.bool(forKey: "autocryptEnabled") ?? false
    }

    nonisolated func setAutocryptEnabled(_ enabled: Bool) {
        Self.defaults?.set(enabled, forKey: "autocryptEnabled")
    }

    func listPublicKeys() async throws -> [KeyInfo] {
        let proxy = try connection.proxy()
        return try await withCheckedThrowingContinuation { continuation in
            proxy.listPublicKeys { keyListJSON, error in
                if let error { continuation.resume(throwing: error); return }
                guard let keyListJSON else {
                    continuation.resume(returning: [])
                    return
                }
                continuation.resume(with: keyListJSON, as: [KeyInfo].self)
            }
        }
    }

    func deleteKey(fingerprint: String) async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.deleteKey(fingerprint: fingerprint) { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    func lsignKey(fingerprint: String) async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.lsignKey(fingerprint: fingerprint) { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    func setTrust(fingerprint: String, level: TrustLevel) async throws {
        let proxy = try connection.proxy()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            proxy.setTrust(fingerprint: fingerprint, level: level.rawValue) { error in
                if let error { continuation.resume(throwing: error); return }
                continuation.resume()
            }
        }
    }

    // MARK: - Default signing key (UserDefaults, no XPC needed)

    private static let defaults = UserDefaults(suiteName: "group.net.pyxzl.mailgpg")

    func getDefaultSigningKey() -> String? {
        Self.defaults?.string(forKey: "defaultSigningKeyFingerprint")
    }

    func setDefaultSigningKey(_ fingerprint: String?) {
        Self.defaults?.set(fingerprint, forKey: "defaultSigningKeyFingerprint")
    }

    // MARK: - Keyservers (UserDefaults, no XPC needed)

    /// Only servers that verify address ownership before serving a UID.
    ///
    /// keyserver.ubuntu.com and the rest of the SKS lineage accept an upload
    /// from anyone claiming any address, so a stranger can publish a key
    /// bearing your correspondent's email and have it auto-imported and used.
    /// Add one back manually in Keyserver settings if you knowingly need it.
    static let defaultKeyservers = [
        "hkps://keys.openpgp.org",
        "hkps://keys.mailvelope.com",
    ]

    // MARK: - Pinned recipient keys (trust on first use)

    private static let pinnedKeysDefault = "pinnedKeys"

    /// The fingerprint last used for this address, if any.
    nonisolated func pinnedFingerprint(for email: String) -> String? {
        let map = Self.defaults?.dictionary(forKey: Self.pinnedKeysDefault) as? [String: String]
        return map?[email.lowercased()]
    }

    /// Record the fingerprint now in use for this address.
    nonisolated func pin(fingerprint: String, for email: String) {
        var map = (Self.defaults?.dictionary(forKey: Self.pinnedKeysDefault) as? [String: String]) ?? [:]
        map[email.lowercased()] = fingerprint
        Self.defaults?.set(map, forKey: Self.pinnedKeysDefault)
    }

    // MARK: - Evidence that a correspondent actually uses PGP

    private static let encryptedSendsDefault = "encryptedSendsByAddress"
    private static let pgpReceivedDefault    = "pgpReceivedFromAddress"

    /// Note that we successfully encrypted a message to this address.
    nonisolated func recordEncryptedSend(to email: String) {
        var map = (Self.defaults?.dictionary(forKey: Self.encryptedSendsDefault) as? [String: Date]) ?? [:]
        map[email.lowercased()] = Date()
        Self.defaults?.set(map, forKey: Self.encryptedSendsDefault)
    }

    /// Note that a signed or encrypted message arrived from this address, or
    /// that it advertised a key by Autocrypt.
    nonisolated func recordPGPReceived(from email: String) {
        let key = email.lowercased()
        var map = (Self.defaults?.dictionary(forKey: Self.pgpReceivedDefault) as? [String: Date]) ?? [:]
        // Only write when the day changed, so routine mail reading does not
        // rewrite the defaults on every message Mail indexes.
        if let seen = map[key], Calendar.current.isDateInToday(seen) { return }
        map[key] = Date()
        Self.defaults?.set(map, forKey: Self.pgpReceivedDefault)
    }

    private static let wkdKeysDefault = "wkdKeyForAddress"

    /// Note that this address publishes a key through Web Key Directory.
    nonisolated func recordWKDKey(for email: String) {
        let key = email.lowercased()
        var map = (Self.defaults?.dictionary(forKey: Self.wkdKeysDefault) as? [String: Date]) ?? [:]
        if let seen = map[key], Calendar.current.isDateInToday(seen) { return }
        map[key] = Date()
        Self.defaults?.set(map, forKey: Self.wkdKeysDefault)
    }

    /// Whether this address has ever demonstrated it can handle PGP.
    ///
    /// A key on a keyserver is not evidence — anyone can upload one, nothing
    /// ever expires off, and a key its owner forgot ten years ago looks exactly
    /// like a live one. A key served from the recipient's own domain by Web Key
    /// Directory is different: someone maintains that publication today.
    ///
    /// Evidence is therefore: mail they sent with PGP on it, mail we
    /// successfully encrypted to them before, or a key published via WKD.
    nonisolated func hasPGPEvidence(for email: String) -> Bool {
        let key = email.lowercased()
        let sent = Self.defaults?.dictionary(forKey: Self.encryptedSendsDefault) as? [String: Date]
        let recv = Self.defaults?.dictionary(forKey: Self.pgpReceivedDefault) as? [String: Date]
        let wkd  = Self.defaults?.dictionary(forKey: Self.wkdKeysDefault) as? [String: Date]
        return sent?[key] != nil || recv?[key] != nil || wkd?[key] != nil
    }

    /// Whether signing and encryption are offered only for addresses with
    /// evidence of PGP use.
    ///
    /// Off by default. The policy withholds a working feature on the strength
    /// of a judgement about someone else's mail client, so it should be a
    /// choice rather than something that quietly happens to you — and when it
    /// misjudges, the symptom is an extension that appears broken.
    nonisolated func getKnownCorrespondentsOnly() -> Bool {
        Self.defaults?.object(forKey: "knownCorrespondentsOnly") as? Bool ?? false
    }

    nonisolated func setKnownCorrespondentsOnly(_ enabled: Bool) {
        Self.defaults?.set(enabled, forKey: "knownCorrespondentsOnly")
    }

    /// Whether outgoing encrypted mail hides its Subject line. Off by default.
    nonisolated func getProtectSubject() -> Bool {
        Self.defaults?.bool(forKey: "protectSubject") ?? false
    }

    nonisolated func setProtectSubject(_ enabled: Bool) {
        Self.defaults?.set(enabled, forKey: "protectSubject")
    }

    nonisolated func getKeyservers() -> [String] {
        Self.defaults?.stringArray(forKey: "keyservers") ?? Self.defaultKeyservers
    }

    nonisolated func setKeyservers(_ servers: [String]) {
        Self.defaults?.set(servers, forKey: "keyservers")
    }
}

// MARK: - Continuation helpers

/// Makes resuming a continuation from an XPC reply block more concise.
private extension CheckedContinuation where T == Data, E == Error {
    func resume(with result: Data?, error: Error?) {
        if let error { resume(throwing: error); return }
        guard let result else { resume(throwing: GPGXPCError.make(.encodingFailed)); return }
        resume(returning: result)
    }
}

private extension CheckedContinuation where E == Error, T: Decodable {
    /// Decode JSON data and resume the continuation with the decoded value.
    func resume(with data: Data, as type: T.Type) {
        do {
            resume(returning: try xpcDecode(type, from: data))
        } catch {
            resume(throwing: error)
        }
    }
}

// MARK: - OneShotRelay

/// Thread-safe wrapper around a CheckedContinuation that guarantees exactly
/// one resume call even when two paths race (XPC reply vs. connection drop).
/// Used exclusively by ping() to avoid continuation leaks when the host app
/// is not running and XPC drops the reply block.
private final class OneShotRelay<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private let continuation: CheckedContinuation<T, Error>

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(returning: value)
    }

    func resume(throwing error: Error) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(throwing: error)
    }
}
