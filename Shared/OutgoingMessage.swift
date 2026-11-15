// OutgoingMessage.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import CryptoKit
import Foundation

nonisolated enum RecipientKeyStatus: Equatable {
    case found
    case notFound
    /// A key exists, but it is not the one last used for this address.
    case keyChanged
    case loading
}

/// The decisions `encode()` makes before it calls GPG: whom to encrypt to and
/// whether an earlier result still fits the message.
///
/// Lives in `Shared` so it can be tested; the extension's own sources are not
/// compiled into the test target.
nonisolated enum OutgoingMessage {

    struct Recipients: Equatable {
        var visible: [String] = []
        /// Bcc recipients, encrypted to as hidden recipients so the To line
        /// cannot read who else received the message.
        var hidden: [String] = []
    }

    enum RecipientProblem: Error, Equatable {
        /// No compose window state for this message: Send Later, a closed
        /// window, or a message without its session header.
        case noComposeState
        case keyChanged([String])
        case missingKeys([String])
        /// The recipient annotation has not finished, or not yet run, for
        /// these addresses.
        case stillLoading([String])
    }

    /// The errors for a message Mail handed over without its data while
    /// signing or encryption is on. Returning no message and no error tells
    /// Mail there is nothing to do, and it sends the plaintext.
    static func missingDataErrors(shouldSign: Bool, shouldEncrypt: Bool) -> (signing: NSError?, encryption: NSError?) {
        let error = NSError(domain: "net.pyxzl.mailgpg", code: 6, userInfo: [NSLocalizedDescriptionKey:
            "Mail did not hand over the message to sign or encrypt. Try sending it again."])
        return (shouldSign ? error : nil, shouldEncrypt ? error : nil)
    }

    /// The fingerprints to encrypt to: one for every To, Cc and Bcc address,
    /// or the reason there is not.
    ///
    /// Every address needs a key that the compose window resolved for it.
    /// An address with no status entry was added after the last annotation
    /// run; letting it through encrypted the message without that person's
    /// key. Without compose state there is nothing to go by, and guessing at
    /// another window's keys is how a message gets encrypted to strangers.
    static func recipients(visible: [String], blind: [String],
                           status: [String: RecipientKeyStatus]?,
                           fingerprints: [String: String]) -> Result<Recipients, RecipientProblem> {
        let visible = unique(visible.filter { !$0.isEmpty })
        let blind = unique(blind.filter { !$0.isEmpty && !visible.contains($0) })
        let all = visible + blind
        guard !all.isEmpty else { return .success(Recipients()) }
        guard let status else { return .failure(.noComposeState) }

        let changed = all.filter { status[$0] == .keyChanged }
        if !changed.isEmpty { return .failure(.keyChanged(changed)) }
        let missing = all.filter {
            status[$0] == .notFound || (status[$0] == .found && fingerprints[$0] == nil)
        }
        if !missing.isEmpty { return .failure(.missingKeys(missing)) }
        let loading = all.filter { status[$0] == nil || status[$0] == .loading }
        if !loading.isEmpty { return .failure(.stillLoading(loading)) }

        let visibleFingerprints = unique(visible.compactMap { fingerprints[$0] })
        // A key carrying several UIDs can serve both a visible and a blind
        // address; keeping it visible is correct, so drop the duplicate.
        let hiddenFingerprints = unique(blind.compactMap { fingerprints[$0] })
            .filter { !visibleFingerprints.contains($0) }
        return .success(Recipients(visible: visibleFingerprints, hidden: hiddenFingerprints))
    }

    /// Headers that change between Mail's encode calls for one message
    /// without changing what it says.
    private static let volatileHeaders: Set<String> = ["date", "message-id", "x-universally-unique-identifier"]

    /// Key for the encode cache, or nil when the message cannot be cached.
    ///
    /// The message UUID alone made a failed send that the user then edited,
    /// re-addressed or switched to unencrypted go out as the old ciphertext.
    /// Everything that decides the output is in the key: the flags, the
    /// addresses (Bcc is not in the headers), the fingerprints and the
    /// message itself, minus the headers that differ between Mail's calls.
    static func cacheKey(messageUUID: String?, shouldSign: Bool, shouldEncrypt: Bool,
                         addresses: [String], recipients: Recipients, rawData: Data) -> String? {
        guard let messageUUID else { return nil }
        return [
            messageUUID,
            "sign=\(shouldSign)", "encrypt=\(shouldEncrypt)",
            addresses.sorted().joined(separator: ","),
            recipients.visible.sorted().joined(separator: ","),
            recipients.hidden.sorted().joined(separator: ","),
            contentDigest(rawData),
        ].joined(separator: "|")
    }

    /// SHA-256 over the message without its volatile headers.
    static func contentDigest(_ data: Data) -> String {
        var hasher = SHA256()
        guard let end = RawMessage.endOfHeaders(in: data) else {
            hasher.update(data: data)
            return hasher.finalize().map { String(format: "%02x", $0) }.joined()
        }
        // Lenient: only used for hashing, so a stray byte only needs to hash
        // the same way each time.
        // swiftlint:disable:next optional_data_string_conversion
        let block = String(decoding: data[..<end.lowerBound], as: UTF8.self)
        var keep = true
        for line in block.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            if line.first != " " && line.first != "\t" {
                let name = line.prefix { $0 != ":" }.trimmingCharacters(in: .whitespaces).lowercased()
                keep = !volatileHeaders.contains(name) && !name.hasPrefix("x-apple-")
            }
            if keep { hasher.update(data: Data((line + "\n").utf8)) }
        }
        hasher.update(data: Data("\n".utf8))
        hasher.update(data: data[end.upperBound...])
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}
