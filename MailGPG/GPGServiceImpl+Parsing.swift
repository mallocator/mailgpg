// GPGServiceImpl+Parsing.swift
// MailGPG (host app only)

import Foundation

extension GPGServiceImpl {

    // MARK: - Colon-format key parser

    /// Parse the output of `gpg --with-colons [--list-keys | --list-secret-keys]`
    /// into an array of `KeyInfo` values.
    ///
    /// GPG's colon format (documented in `doc/DETAILS` in the GPG source):
    ///   type:validity:keylen:algo:keyid:created:expires:...:uid-or-fingerprint:
    ///
    /// Record types we care about:
    ///   sec / pub  — primary key line (starts a new key block)
    ///   fpr        — fingerprint (field 9)
    ///   uid        — user-id "Name (comment) <email>" (field 9)
    func parseColonOutput(_ output: String, wantSecretKeys: Bool) -> [KeyInfo] {
        var results: [KeyInfo] = []

        // Per-key accumulator. One KeyInfo is emitted per key, not per user ID:
        // several entries sharing a fingerprint would collide as Identifiable
        // rows in the key lists, and the addresses belong to one key anyway.
        var inKey = false
        var fingerprint = ""
        var keyID       = ""
        var validity    = ""   // field[1] on the pub/sec record
        var ownertrust  = ""   // field[8]: explicitly-set owner trust
        var expiry      = ""
        var created     = ""
        var uids: [(name: String, email: String, revoked: Bool)] = []

        func flush() {
            guard inKey, !fingerprint.isEmpty, !uids.isEmpty else { return }
            let live = uids.filter { !$0.revoked }
            // Display the first listed user ID even if every one is revoked, so
            // the key is still recognisable in the key list.
            let display = live.first ?? uids[0]
            let expiryDate:  Date? = Double(expiry).map  { Date(timeIntervalSince1970: $0) }
            let createdDate: Date? = Double(created).map { Date(timeIntervalSince1970: $0) }
            let trust: TrustLevel = ownertrust == "n" ? .none
                                  : TrustLevel(rawValue: ownertrust) ?? .unknown
            let validityLevel: TrustLevel = validity == "n" ? .none
                                          : TrustLevel(rawValue: validity) ?? .unknown
            results.append(KeyInfo(
                fingerprint: fingerprint,
                keyID:       fingerprint.count >= 8 ? String(fingerprint.suffix(8)) : keyID,
                email:       display.email,
                name:        display.name,
                trustLevel:  trust,
                validity:    validityLevel,
                hasSecretKey: wantSecretKeys,
                expiresAt:   expiryDate,
                createdAt:   createdDate,
                isRevoked:   validity == "r",
                // Revoked user IDs are excluded: the owner retired that address,
                // and encrypting to it or accepting a signature from it should
                // not keep working because the key as a whole is still valid.
                emails:      live.map { $0.email.lowercased() }.filter { !$0.isEmpty }
            ))
        }

        for raw in output.components(separatedBy: "\n") {
            let line = raw.hasSuffix("\r") ? String(raw.dropLast()) : raw
            let f    = line.components(separatedBy: ":")
            guard let type = f.first else { continue }

            switch type {
            case "sec"  where wantSecretKeys,   // secret key available locally
                 "sec#" where wantSecretKeys,    // stub only — key lives on smartcard/YubiKey
                 "pub"  where !wantSecretKeys:
                flush()
                inKey       = true
                keyID       = f.count > 4 ? f[4] : ""
                validity    = f.count > 1 ? f[1] : ""
                ownertrust  = f.count > 8 ? f[8] : ""
                expiry      = f.count > 6 ? f[6] : ""
                created     = f.count > 5 ? f[5] : ""   // colon field 6: creation date
                fingerprint = ""
                uids        = []

            case "pub" where wantSecretKeys:
                // A bare `pub` record inside --list-secret-keys output means
                // we've moved past the secret key block — stop collecting.
                flush()
                inKey = false
                uids  = []

            case "fpr" where inKey && fingerprint.isEmpty:
                fingerprint = f.count > 9 ? f[9] : ""

            case "uid" where inKey && !fingerprint.isEmpty:
                let uidValidity = f.count > 1 ? f[1] : ""
                let (name, email) = parseUID(unescapeColonField(f.count > 9 ? f[9] : ""))
                uids.append((name: name,
                             email: email,
                             revoked: uidValidity == "r" || uidValidity == "e"))

            default: break
            }
        }
        flush()
        return results
    }

    /// Undo the escaping GPG applies to colon-delimited fields.
    ///
    /// A user ID containing a colon arrives as `Alice\x3a The Boss`, and a
    /// backslash as `\x5c`. Left as-is those sequences show up verbatim in the
    /// key list, and any address containing one would never match.
    func unescapeColonField(_ value: String) -> String {
        guard value.contains("\\x") else { return value }
        var out = ""
        var index = value.startIndex
        while index < value.endIndex {
            if value[index] == "\\",
               let x = value.index(index, offsetBy: 1, limitedBy: value.endIndex),
               x < value.endIndex, value[x] == "x",
               let end = value.index(index, offsetBy: 4, limitedBy: value.endIndex),
               let byte = UInt8(value[value.index(index, offsetBy: 2)..<end], radix: 16),
               let scalar = Unicode.Scalar(UInt32(byte)) {
                out.append(Character(scalar))
                index = end
                continue
            }
            out.append(value[index])
            index = value.index(after: index)
        }
        return out
    }

    /// Parse a GPG user-ID string in the form `"Name (comment) <email>"`.
    func parseUID(_ uid: String) -> (name: String, email: String) {
        if let lt = uid.lastIndex(of: "<"),
           let gt = uid.lastIndex(of: ">"), lt < gt {
            let email = String(uid[uid.index(after: lt)..<gt])
            var name  = String(uid[..<lt]).trimmingCharacters(in: .whitespaces)
            // Drop "(comment)" portion if present.
            if let paren = name.firstIndex(of: "(") {
                name = String(name[..<paren]).trimmingCharacters(in: .whitespaces)
            }
            return (name, email)
        }
        return (uid, "")
    }

    // MARK: - GPG status parsers

    /// Parse the `[GNUPG:]` status lines GPG writes to its status file
    /// is used during decryption. Returns a `SecurityStatus` describing what happened.
    ///
    /// Key status tokens:
    ///   DECRYPTION_OKAY           — successfully decrypted
    ///   GOODSIG <keyID> <name>    — a valid signature was found
    ///   BADSIG  <keyID> <name>    — signature present but invalid (tampered?)
    ///   NO_PUBKEY <keyID>         — can't verify: public key not in keychain
    func parseDecryptStatus(status: String) -> SecurityStatus {
        var pending: [(email: String, keyID: String)] = []
        var fingerprintByKeyID: [String: String] = [:]  // keyID → full fingerprint from VALIDSIG
        var lastKeyID: String? = nil
        var isEncrypted = false

        for line in status.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] DECRYPTION_OKAY") {
                isEncrypted = true
            } else if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    let keyID = p[2]
                    // GOODSIG name field is the full UID string "Name <email>"
                    let (_, email) = parseUID(p[3...].joined(separator: " "))
                    pending.append((email: email, keyID: keyID))
                    lastKeyID = keyID
                }
            } else if line.contains("[GNUPG:] VALIDSIG"), let kid = lastKeyID {
                let p = line.components(separatedBy: " ")
                if p.count >= 3 { fingerprintByKeyID[kid] = p[2] }
                lastKeyID = nil
            } else if line.contains("[GNUPG:] BADSIG") {
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(reason: "Bad signature from key \(keyID)")
            } else if line.contains("[GNUPG:] REVKEYSIG") {
                // The maths checked out, but the signer revoked this key. GPG
                // emits this instead of GOODSIG, so without an explicit branch
                // it reads as "no signature" — far weaker than what happened.
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(
                    reason: "Signed with key \(keyID), which its owner has revoked. "
                          + "Treat this signature as worthless.")
            } else if line.contains("[GNUPG:] EXPKEYSIG") {
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(
                    reason: "Signed with key \(keyID), which has expired.")
            } else if line.contains("[GNUPG:] EXPSIG") {
                return .signatureInvalid(reason: "The signature itself has expired.")
            } else if line.contains("[GNUPG:] NO_PUBKEY") {
                let p = line.components(separatedBy: " ")
                let keyID = p.count >= 3 ? p[2] : "unknown"
                return .keyNotFound(keyID: keyID)
            }
        }

        let signers = pending.map { s in
            Signer(email: s.email, keyID: s.keyID,
                   fingerprint: fingerprintByKeyID[s.keyID] ?? s.keyID,
                   trustLevel: .unknown)
        }
        if isEncrypted { return .encrypted(signers: signers) }
        if !signers.isEmpty { return .signed(signers: signers) }
        return .plain
    }

    /// Parse status lines from `gpg --verify`, read from the status file.
    func parseVerifyStatus(status: String) -> SecurityStatus {
        let combined = status
        var keyID: String? = nil
        var name: String? = nil
        var fingerprint: String? = nil

        for line in combined.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 {
                    keyID = p[2]
                    // GOODSIG name field is the full UID string "Name <email>"
                    let (_, email) = parseUID(p[3...].joined(separator: " "))
                    name = email.isEmpty ? p[3...].joined(separator: " ") : email
                }
            } else if line.contains("[GNUPG:] VALIDSIG"), keyID != nil {
                let p = line.components(separatedBy: " ")
                if p.count >= 3 { fingerprint = p[2] }
            } else if line.contains("[GNUPG:] BADSIG") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(reason: "Bad signature from key \(kid)")
            } else if line.contains("[GNUPG:] REVKEYSIG") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(
                    reason: "Signed with key \(kid), which its owner has revoked. "
                          + "Treat this signature as worthless.")
            } else if line.contains("[GNUPG:] EXPKEYSIG") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .signatureInvalid(
                    reason: "Signed with key \(kid), which has expired.")
            } else if line.contains("[GNUPG:] EXPSIG") {
                return .signatureInvalid(reason: "The signature itself has expired.")
            } else if line.contains("[GNUPG:] NO_PUBKEY") {
                let p = line.components(separatedBy: " ")
                let kid = p.count >= 3 ? p[2] : "unknown"
                return .keyNotFound(keyID: kid)
            }
        }

        if let keyID, let name {
            let fp = fingerprint ?? keyID
            return .signed(signers: [Signer(email: name, keyID: keyID, fingerprint: fp, trustLevel: .unknown)])
        }
        // No GOODSIG in the status output means the signature did not verify.
        // There is deliberately no fallback to scraping human-readable output —
        // that text carries attacker-chosen user IDs.
        return .signatureInvalid(reason: "No valid signature found")
    }

    /// Look up each signer's trust level in the local keyring and return an
    /// updated `SecurityStatus` with the real `trustLevel` filled in.
    /// Falls back to `.unknown` for any key that can't be found locally.
    func enrichWithTrust(_ status: SecurityStatus) -> SecurityStatus {
        func trust(forFingerprint fp: String) -> TrustLevel {
            guard let fp = try? validatedKeyIdentifier(fp, fieldName: "fingerprint", allowShort: false)
            else { return .unknown }
            guard let (out, _, code) = try? gpg(["--list-keys", "--with-colons",
                                                  "--fixed-list-mode", fp]),
                  code == 0 else { return .unknown }
            // Use validity (lsign/web-of-trust result) rather than ownertrust so the
            // trust badge in the UI reflects whether the key has actually been verified.
            return parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                    wantSecretKeys: false).first?.validity ?? .unknown
        }
        func enrich(_ signers: [Signer]) -> [Signer] {
            signers.map { Signer(email: $0.email, keyID: $0.keyID,
                                 fingerprint: $0.fingerprint,
                                 trustLevel: trust(forFingerprint: $0.fingerprint)) }
        }
        switch status {
        case .encrypted(let signers): return .encrypted(signers: enrich(signers))
        case .signed(let signers):    return .signed(signers: enrich(signers))
        default:                      return status
        }
    }

    /// Extract the sender's email address from a raw RFC 2822 message's `From:` header.
    /// Handles both `"Name <email>"` and plain `"email"` forms.
    func extractFromEmail(from data: Data) -> String? {
        let str = String(data: data, encoding: .utf8) ?? ""
        for line in str.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.lowercased().hasPrefix("from:") else { continue }
            let value = String(trimmed.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            if let lt = value.firstIndex(of: "<"), let gt = value.firstIndex(of: ">"), lt < gt {
                return String(value[value.index(after: lt)..<gt])
            }
            if value.contains("@") { return value }
        }
        return nil
    }

    /// Extract the fingerprint from `[GNUPG:] IMPORT_OK <flags> <fingerprint>` status output.
    func parseImportedFingerprint(from statusOutput: String) -> String? {
        for line in statusOutput.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] IMPORT_OK") {
                let p = line.components(separatedBy: " ")
                if p.count >= 4 { return p[3] }
            }
        }
        return nil
    }
}
