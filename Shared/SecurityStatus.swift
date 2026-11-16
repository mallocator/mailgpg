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
    /// Validity of this key in the local GPG keyring: the key's own until
    /// `vouching(for:)` narrows it to the user ID of the sender's address.
    let trustLevel: TrustLevel
    /// Every live address on the signing key, lowercased, from the local
    /// keyring. GPG's status output names only the primary user ID, whichever
    /// address the message was signed for.
    var emails: [String] = []
    /// Validity of the user ID carrying each address in `emails`.
    var addressValidity: [String: TrustLevel] = [:]
    /// Convenience: true when trust is full or ultimate.
    var trusted: Bool { trustLevel == .full || trustLevel == .ultimate }

    /// Whether `address` is one of the signing key's live user IDs.
    func hasAddress(_ address: String) -> Bool {
        emails.contains(address.lowercased())
    }

    /// This signer with the trust of the user ID carrying `address`, the one
    /// the message claims to come from. A key verified for one address says
    /// nothing about another user ID on it.
    func vouching(for address: String) -> Signer {
        Signer(email: email, keyID: keyID, fingerprint: fingerprint,
               trustLevel: addressValidity[address.lowercased()] ?? .unknown,
               emails: emails, addressValidity: addressValidity)
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

extension SecurityStatus {
    /// The status of a message signed and encrypted in two layers: a
    /// multipart/signed entity inside the ciphertext (mutt, KMail), or a
    /// multipart/encrypted entity inside a signature. `decryption` is gpg's
    /// status for the encrypted layer, `signature` the verification of the
    /// other one.
    ///
    /// A failure in either layer is the message's status: a signature that
    /// does not verify, or an embedded one that does not, must not be hidden by
    /// the layer that worked. Otherwise the signers of both layers count, once
    /// each, and the message is encrypted when gpg decrypted it.
    static func nested(decryption: SecurityStatus, signature: SecurityStatus) -> SecurityStatus {
        guard case .signed(let verified) = signature else { return signature }
        func joined(_ embedded: [Signer]) -> [Signer] {
            var seen = Set<String>()
            return (embedded + verified).filter { seen.insert($0.fingerprint).inserted }
        }
        switch decryption {
        case .encrypted(let embedded): return .encrypted(signers: joined(embedded))
        case .signed(let embedded):    return .signed(signers: joined(embedded))
        default:                       return decryption
        }
    }

    /// Whether this status, from gpg --decrypt, says it decrypted anything:
    /// only DECRYPTION_OKAY does. gpg --decrypt also succeeds on an opaque
    /// signed message or a stored literal, which were never encrypted. The
    /// signer check may turn the status into an invalid signature, so ask the
    /// status from before it.
    var isDecrypted: Bool {
        if case .encrypted = self { return true }
        return false
    }
}
