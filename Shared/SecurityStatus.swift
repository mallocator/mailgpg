// SecurityStatus.swift
// MailGPGExtension

/// A single PGP signer attached to a message.
struct Signer: Equatable, Codable {
    /// The address GPG names for the signature: the key's primary user ID.
    let email: String
    /// Short key ID shown in the UI (last 8 hex chars of the fingerprint).
    let keyID: String
    /// Full 40-char hex fingerprint.
    let fingerprint: String
    /// Owner-trust level of this key in the local GPG keychain.
    let trustLevel: TrustLevel
    /// Every live address on the signing key, lowercased, from the local
    /// keyring. GPG's status output names only the primary user ID, whichever
    /// address the message was signed for.
    var emails: [String] = []
    /// Convenience: true when trust is full or ultimate.
    var trusted: Bool { trustLevel == .full || trustLevel == .ultimate }

    /// Whether `address` is one of the signing key's live user IDs.
    func hasAddress(_ address: String) -> Bool {
        emails.contains(address.lowercased())
    }
}

/// The PGP security state of a received message.
enum SecurityStatus: Equatable, Codable {
    /// Message was encrypted. May also carry verified signatures.
    case encrypted(signers: [Signer])
    /// Message was not encrypted but carries one or more valid signatures.
    case signed(signers: [Signer])
    /// A signature was present but verification failed (e.g. tampered content).
    case signatureInvalid(reason: String)
    /// The message was encrypted but we could not decrypt it.
    case decryptionFailed(reason: String)
    /// Signed or encrypted with a key we don't have locally and couldn't fetch.
    case keyNotFound(keyID: String)
    /// No PGP content detected.
    case plain
}
