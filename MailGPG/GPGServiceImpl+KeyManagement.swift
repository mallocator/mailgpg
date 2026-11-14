// GPGServiceImpl+KeyManagement.swift
// MailGPG (host app only)

import Foundation
import os

extension GPGServiceImpl {

    // MARK: - Key management

    func lookupKey(email: String,
                   reply: @escaping (Data?, Error?) -> Void) {
        do {
            if let key = try resolveKey(email: email, forEncryption: true) {
                reply(try xpcEncode(key), nil)
            } else {
                reply(nil, nil)
            }
        } catch {
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    /// Resolve a key by email address and/or key ID.
    ///
    /// Lookup order:
    ///   1. Local keyring by email (fast, no network)
    ///   2. WKD + default keyserver by email (`--locate-keys`)
    ///   3. Each extra keyserver by email (`--locate-keys --keyserver <url>`)
    ///   4. Each keyserver by key ID (`--recv-keys`) — only when `keyID` is given
    ///
    /// Returns the best usable key found, or `nil` if none was found.
    /// Keys are auto-imported by GPG on steps 2–4. `forEncryption` skips keys
    /// without a usable encryption subkey in the lookups by address.
    func resolveKey(email: String? = nil, keyID: String? = nil, forEncryption: Bool = false) throws -> KeyInfo? {
        let keyservers = currentKeyservers()

        // gpg reads options after operands too, so an address from a mail
        // header such as `--log-file=/path/x@y` would set an option. `--`
        // ends the options; no real address starts with a dash.
        if let email, !email.hasPrefix("-") {
            // ── Step 1: local keyring by email ───────────────────────────
            let (localOut, _, localCode) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode", "--", email])
            if localCode == 0, let key = usableKey(for: email, in:
                parseColonOutput(String(data: localOut, encoding: .utf8) ?? "", wantSecretKeys: false),
                forEncryption: forEncryption) {
                return key
            }

            // ── Step 2: Web Key Directory, on its own ─────────────────────
            // Run separately from the keyservers rather than as one combined
            // --auto-key-locate list, so the caller can tell WKD apart. A WKD
            // hit says the recipient's own mail domain publishes this key for
            // this address right now; a keyserver hit says only that somebody
            // uploaded it at some point.
            let (wkdOut, _, wkdCode) = try gpg([
                "--locate-keys",
                "--auto-key-locate", "wkd",
                "--keyserver-options", "timeout=10",
                "--no-auto-check-trustdb",
                "--with-colons", "--fixed-list-mode",
                "--", email
            ])
            if wkdCode == 0, var key = usableKey(for: email, in:
                parseColonOutput(String(data: wkdOut, encoding: .utf8) ?? "", wantSecretKeys: false),
                forEncryption: forEncryption) {
                key.viaWKD = true
                log.info("resolveKey: found via WKD")
                return key
            }

            // ── Step 3: keyservers by email ───────────────────────────────
            // --keyserver-options timeout=10: don't block indefinitely.
            // --no-auto-check-trustdb: skip trust-DB rebuild (~1 s saved).
            for ks in keyservers {
                let (out, _, code) = try gpg([
                    "--keyserver", ks,
                    "--locate-keys",
                    "--auto-key-locate", "keyserver",
                    "--keyserver-options", "timeout=10",
                    "--no-auto-check-trustdb",
                    "--with-colons", "--fixed-list-mode",
                    "--", email
                ])
                guard code == 0, let key = usableKey(for: email, in:
                    parseColonOutput(String(data: out, encoding: .utf8) ?? "", wantSecretKeys: false),
                    forEncryption: forEncryption)
                else { continue }
                return key
            }
        }

        // ── Step 4: recv-keys by key ID across all keyservers ────────────
        // --recv-keys produces no colon output, so after a successful import
        // do a local --list-keys to get a proper KeyInfo to return.
        if let keyID {
            let keyID = try validatedKeyIdentifier(keyID, fieldName: "key ID")
            for ks in keyservers {
                guard (try gpg(["--keyserver", ks, "--recv-keys",
                                "--keyserver-options", "timeout=10", keyID])).exitCode == 0
                else { continue }
                log.info("resolveKey: recv-keys succeeded on configured keyserver")
                let (listOut, _, _) = try gpg(
                    ["--list-keys", "--with-colons", "--fixed-list-mode", keyID])
                return parseColonOutput(String(data: listOut, encoding: .utf8) ?? "",
                                        wantSecretKeys: false).first
            }
        }

        return nil
    }

    /// The key for `email` out of a gpg listing searched by that address.
    ///
    /// gpg matches a bare address as a substring of the user ID, so the
    /// listing for bob@example.com also holds `Mallory <notbob@example.com>`.
    /// Only a key carrying the address itself as a live user ID qualifies —
    /// primary or not — and an unexpired one wins over an expired one. For
    /// encryption, only a key that can still encrypt qualifies.
    func usableKey(for email: String, in keys: [KeyInfo], forEncryption: Bool = false) -> KeyInfo? {
        let wanted = email.lowercased()
        let carrying = keys.filter {
            !$0.isRevoked && $0.emails.contains(wanted) && (!forEncryption || $0.canEncrypt)
        }
        return carrying.first { $0.expiresAt.map { $0 > Date() } ?? true } ?? carrying.first
    }

    func listSecretKeys(reply: @escaping (Data?, Error?) -> Void) {
        do {
            let (out, _, _) = try gpg(
                ["--list-secret-keys", "--with-colons", "--fixed-list-mode"])
            let keys = parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                        wantSecretKeys: true)
            log.info("listSecretKeys: found \(keys.count) key(s)")
            reply(try xpcEncode(keys), nil)
        } catch {
            Self.logNSError(error as NSError, prefix: "listSecretKeys: error")
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    func listPublicKeys(reply: @escaping (Data?, Error?) -> Void) {
        do {
            let (out, _, _) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode"])
            let keys = parseColonOutput(String(data: out, encoding: .utf8) ?? "",
                                        wantSecretKeys: false)
            log.info("listPublicKeys: found \(keys.count) key(s)")
            reply(try xpcEncode(keys), nil)
        } catch {
            Self.logNSError(error as NSError, prefix: "listPublicKeys: error")
            reply(nil, GPGXPCError.make(.gpgFailed, message: error.localizedDescription))
        }
    }

    func deleteKey(fingerprint: String,
                   reply: @escaping (Error?) -> Void) {
        do {
            let fingerprint = try validatedKeyIdentifier(fingerprint, fieldName: "fingerprint", allowShort: false)
            let (_, stderr, code) = try gpg(
                ["--batch", "--yes", "--delete-keys", fingerprint])
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg delete-keys failed: \(stderr)")
            }
            log.info("deleteKey: deleted key")
            reply(nil)
        } catch {
            Self.logNSError(error as NSError, prefix: "deleteKey: error")
            reply(error as NSError)
        }
    }

    func setTrust(fingerprint: String,
                  level: String,
                  reply: @escaping (Error?) -> Void) {
        guard let trustLevel = TrustLevel(rawValue: level) else {
            reply(GPGXPCError.make(.encodingFailed,
                message: "Unknown trust level: \(level)"))
            return
        }
        do {
            let fingerprint = try validatedKeyIdentifier(fingerprint, fieldName: "fingerprint", allowShort: false)
            // --import-ownertrust reads "<fingerprint>:<numeric value>:\n" lines.
            // Writing to a temp file is more reliable than stdin when GPG runs
            // non-interactively (some builds ignore stdin with --no-tty).
            let ownertrustLine = "\(fingerprint):\(trustLevel.gpgOwntrustValue):\n"
            let tmpURL = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("mailgpg-ownertrust-\(UUID().uuidString).txt")
            try ownertrustLine.write(to: tmpURL, atomically: true, encoding: .utf8)
            defer { try? FileManager.default.removeItem(at: tmpURL) }

            let (_, importStderr, importCode) = try gpg(
                ["--batch", "--import-ownertrust", tmpURL.path])
            log.info("setTrust import: code=\(importCode)")
            guard importCode == 0 else {
                throw GPGXPCError.make(.gpgFailed,
                    message: "gpg import-ownertrust failed (code \(importCode)): \(importStderr)")
            }

            // Recompute the trust database so that --list-keys reflects the
            // new ownertrust immediately (without this, 'gpg -k' still shows the
            // old calculated validity until GPG decides to rebuild on its own).
            let (_, _, checkCode) = try gpg(["--batch", "--check-trustdb"])
            if checkCode != 0 {
                log.warning("setTrust check-trustdb: code=\(checkCode)")
            }

            log.info("setTrust: updated key trust to \(level, privacy: .public)")
            reply(nil)
        } catch {
            Self.logNSError(error as NSError, prefix: "setTrust: error")
            reply(error as NSError)
        }
    }

    func lsignKey(fingerprint: String, reply: @escaping (Error?) -> Void) {
        do {
            let fingerprint = try validatedKeyIdentifier(fingerprint, fieldName: "fingerprint", allowShort: false)
            let (_, stderr, code) = try gpg(["--batch", "--yes", "--lsign-key", fingerprint])
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed, message: "gpg lsign-key failed: \(stderr)")
            }
            _ = try? gpg(["--batch", "--check-trustdb"])
            log.info("lsignKey: locally signed key")
            reply(nil)
        } catch {
            Self.logNSError(error as NSError, prefix: "lsignKey: error")
            reply(error as NSError)
        }
    }

    func importKey(armoredKey: String,
                   reply: @escaping (Data?, Error?) -> Void) {
        guard let keyData = armoredKey.data(using: .utf8) else {
            reply(nil, GPGXPCError.make(.encodingFailed)); return
        }
        importKeyData(keyData: keyData, reply: reply)
    }

    /// Export a public key in binary form for Autocrypt `keydata`.
    /// --export-options export-minimal strips third-party signatures, which
    /// keeps the header small and avoids republishing other people's
    /// certifications through your mail.
    func exportPublicKey(fingerprint: String,
                         reply: @escaping (Data?, Error?) -> Void) {
        do {
            let fingerprint = try validatedKeyIdentifier(
                fingerprint, fieldName: "fingerprint", allowShort: false)
            let (out, stderr, code) = try gpg(
                ["--export", "--export-options", "export-minimal", fingerprint])
            guard code == 0, !out.isEmpty else {
                throw GPGXPCError.make(.gpgFailed, message: "gpg export failed: \(stderr)")
            }
            reply(out, nil)
        } catch {
            reply(nil, error as NSError)
        }
    }

    func importKeyData(keyData: Data,
                       reply: @escaping (Data?, Error?) -> Void) {
        do {
            let (_, stderr, statusText, code) = try gpgWithStatus(
                ["--import", "--batch", "--yes"],
                input: keyData)
            guard code == 0 else {
                throw GPGXPCError.make(.gpgFailed, message: "gpg import failed: \(stderr)")
            }
            guard let fingerprint = parseImportedFingerprint(from: statusText) else {
                throw GPGXPCError.make(.encodingFailed,
                    message: "Could not determine imported key fingerprint")
            }
            let validatedFingerprint = try validatedKeyIdentifier(
                fingerprint,
                fieldName: "imported fingerprint",
                allowShort: false)
            // Fetch full KeyInfo for the freshly-imported key.
            let (listOut, _, _) = try gpg(
                ["--list-keys", "--with-colons", "--fixed-list-mode", validatedFingerprint])
            let keys = parseColonOutput(String(data: listOut, encoding: .utf8) ?? "",
                                        wantSecretKeys: false)
            guard let key = keys.first else {
                throw GPGXPCError.make(.keyNotFound, message: "Imported key not found in keyring")
            }
            reply(try xpcEncode(key), nil)
        } catch {
            reply(nil, error as NSError)
        }
    }
}
