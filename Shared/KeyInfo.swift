// KeyInfo.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// Metadata about a single GPG key (public or secret).
///
/// `Codable` so it can be JSON-encoded and sent as `Data` over XPC.
/// `Identifiable` so SwiftUI lists can use it directly.
struct KeyInfo: Codable, Identifiable, Equatable {
    /// Full 40-character hex fingerprint — the stable, unique identifier.
    let fingerprint: String

    /// Last 8 hex characters of the fingerprint. Shown in the UI.
    let keyID: String

    /// The address shown for this key — the first user ID GPG lists.
    let email: String


    /// Human-readable name from the key's User ID packet.
    let name: String

    /// Owner-trust level (field 8): how much GPG trusts this key owner to certify others.
    let trustLevel: TrustLevel

    /// Calculated validity (field 1): whether this key is considered valid based on
    /// local signatures (`lsign`) and web-of-trust calculations. This is the best
    /// validity of any of its user IDs, so it says nothing about a given address:
    /// use `isTrusted(for:)` for that.
    let validity: TrustLevel

    /// Whether a secret (private) key is available for this fingerprint.
    /// `true` means we can sign or decrypt with this key.
    let hasSecretKey: Bool

    /// Expiry date, or `nil` if the key never expires.
    let expiresAt: Date?

    /// When the key was created. Used to pick the newest key when several
    /// carry the same address — an old key you no longer use should not win a
    /// coin toss against your current one.
    let createdAt: Date?

    /// Whether this key has been revoked by its owner.
    /// A revoked key must not be used for encryption or signing.
    let isRevoked: Bool
    /// Every non-revoked address on this key, lowercased.
    ///
    /// A key routinely carries several user IDs: a work address, a personal
    /// one, an old one. Matching only `email` matched the one GPG lists first,
    /// the primary user ID, so a correspondent reached at any other address on
    /// their own key looked like they had no key.
    var emails: [String] = []

    /// Calculated validity of the user ID carrying each address in `emails`.
    ///
    /// Each user ID is certified on its own. A key lsigned for one address
    /// shows full validity, and a user ID its owner adds later for someone
    /// else's address stays unverified on that key.
    var addressValidity: [String: TrustLevel] = [:]

    /// True when this key was found through Web Key Directory — served over
    /// HTTPS from the recipient's own mail domain, at a path derived from their
    /// address. That means whoever runs their mail publishes this key for this
    /// address today, which is a live statement about the address rather than
    /// something a stranger uploaded once and nobody ever removed.
    var viaWKD: Bool = false

    /// Whether the key has a usable encryption subkey (`E` in the key's
    /// capabilities). A key whose encryption subkey expired or was revoked
    /// still lists, but gpg refuses to encrypt to it.
    var canEncrypt: Bool = true

    /// Whether the user ID carrying `address` has been verified (full or ultimate validity).
    func isTrusted(for address: String) -> Bool {
        let level = addressValidity[address.lowercased()]
        return level == .full || level == .ultimate
    }

    /// The validity of the least verified address on this key: what the key
    /// list and key page show. A key lsigned before its owner added an address
    /// is not verified for that address. A key without addresses has its own.
    var weakestValidity: TrustLevel {
        emails.map { addressValidity[$0] ?? .unknown }.min() ?? validity
    }

    /// Whether every address on this key has been verified.
    var isVerified: Bool { weakestValidity == .full || weakestValidity == .ultimate }

    /// Whether using this key for `address` would silently replace `pinned`,
    /// the fingerprint used for it before. Verifying the user ID for that
    /// address is the deliberate act that accepts a replacement.
    func replacesPin(_ pinned: String?, for address: String) -> Bool {
        guard let pinned, pinned != fingerprint else { return false }
        return !isTrusted(for: address)
    }

    // `Identifiable` — SwiftUI needs a stable `id` property.
    var id: String { fingerprint }
}

extension KeyInfo {
    /// Which of `keys`, all carrying `address`, to use for it: the pinned
    /// fingerprint when it is among them, else the first whose user ID for
    /// `address` is verified, else the first. Another key for the address
    /// listed before the pinned or verified one must not shadow it: the pin
    /// check would then report a changed key though the right one is here.
    static func preferring(_ pinned: String?, for address: String, in keys: [KeyInfo]) -> KeyInfo? {
        keys.first { $0.fingerprint == pinned } ?? keys.first { $0.isTrusted(for: address) } ?? keys.first
    }

    /// One key per address on `keys`, each chosen by `preferring(_:for:in:)`
    /// with that address's pin. A key carrying three user IDs is listed under all three.
    static func keysByAddress(_ keys: [KeyInfo], pinned: (String) -> String?) -> [String: KeyInfo] {
        Dictionary(grouping: keys.flatMap { key in key.emails.map { ($0, key) } }, by: \.0)
            .compactMapValues { pairs in
                preferring(pinned(pairs[0].0), for: pairs[0].0, in: pairs.map(\.1))
            }
    }
}
