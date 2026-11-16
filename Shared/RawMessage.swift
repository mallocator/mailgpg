// RawMessage.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// Byte-level reading of a raw RFC 2822 message, before anything is decoded.
///
/// Lives in `Shared` so it can be tested — the extension's own sources are not
/// compiled into the test target — and so the host app and the extension find
/// the end of the header block the same way.
nonisolated enum RawMessage {

    /// Headers grow past 4 KB (DKIM, ARC, Received, …) but never anywhere near
    /// this. Without a bound, a pure-CRLF message, which contains no "\n\n" at
    /// all, had its whole body scanned for one, on every call for every message.
    static let headerSearchLimit = 256 * 1024

    /// The blank line that ends the header block: whichever of CRLF CRLF and
    /// LF LF comes first within `headerSearchLimit`.
    ///
    /// Trying "\r\n\r\n" before "\n\n" is wrong: if the headers use LF but the
    /// body contains CRLF content (quoted text from a decrypted Mailvelope
    /// message, an attached message), the split lands on a CRLF blank line
    /// *inside the body*, and the body is read as headers.
    static func endOfHeaders(in data: Data) -> Range<Data.Index>? {
        // Data slices share their parent's indices, so ranges found in the
        // window are valid indices into `data`.
        let window = data.prefix(headerSearchLimit)
        let crlf = window.range(of: Data("\r\n\r\n".utf8))
        let lf   = window.range(of: Data("\n\n".utf8))
        switch (crlf, lf) {
        case let (crlf?, lf?): return crlf.lowerBound < lf.lowerBound ? crlf : lf
        case let (crlf?, nil): return crlf
        case let (nil, lf):    return lf
        }
    }

    /// The header block, or the first 4 KB when no blank line ends it.
    static func headerBlock(in data: Data) -> Data {
        endOfHeaders(in: data).map { data[..<$0.lowerBound] } ?? data.prefix(4096)
    }

    /// What `decodedMessage` has to do with a message: decrypt, verify, or
    /// nothing.
    struct PGPContent: Equatable {
        let isEncrypted: Bool
        let isSigned: Bool
    }

    private static let inlineMessageMarker = Data("-----BEGIN PGP MESSAGE-----".utf8)
    private static let inlineSignedMarker = Data("-----BEGIN PGP SIGNED MESSAGE-----".utf8)

    /// Classify a message from its own Content-Type first, and scan the body
    /// for inline armour only when that does not decide.
    ///
    /// Only the top-level Content-Type counts. It is found anywhere in the
    /// header block rather than a fixed prefix: routing headers added by
    /// Gmail, Exchange, etc. (DKIM, ARC, Received, ...) can push it well past
    /// 4 KB. `multipart/signed` or a `boundary=` in any other header is text
    /// the sender chose, and reading it as the message's structure let a
    /// genuine signature vouch for text Mail displays from other parts. When
    /// the Content-Type says RFC 3156, the body is not looked at: a
    /// multipart/signed message quoting an armoured encrypted block was
    /// otherwise taken down the decrypt path, labelled encrypted, and its real
    /// signature never verified. The body scans are byte searches, so ordinary
    /// large messages never become a Swift String.
    static func pgpContent(of data: Data) -> PGPContent {
        if isMIMEEncrypted(data) {
            return PGPContent(isEncrypted: true, isSigned: false)
        }
        if let contentType = contentType(of: data) {
            if mediaType(of: contentType) == "multipart/signed",
               parameter("protocol", in: contentType)?.lowercased() == "application/pgp-signature" {
                return PGPContent(isEncrypted: false, isSigned: true)
            }
        }
        // Inline PGP (e.g. Mailvelope): the armour is in the body.
        return PGPContent(isEncrypted: data.range(of: inlineMessageMarker) != nil,
                          isSigned: data.range(of: inlineSignedMarker) != nil)
    }

    /// Whether the message's own Content-Type is RFC 3156 multipart/encrypted.
    /// Unlike `pgpContent`, the body is not scanned for inline armour: a signed
    /// text part quoting an armoured block is text, not ciphertext to open.
    static func isMIMEEncrypted(_ data: Data) -> Bool {
        guard let contentType = contentType(of: data) else { return false }
        return mediaType(of: contentType) == "multipart/encrypted"
            && parameter("protocol", in: contentType)?.lowercased() == "application/pgp-encrypted"
    }

    /// `message` with its body replaced by `entity`, a MIME entity (headers,
    /// blank line, body) such as the signed part of a multipart/signed message.
    /// The envelope keeps every header but its Content-* ones; the entity's
    /// headers say what the new body is. Written with CRLF throughout, the
    /// canonical form `signedParts` already returns entities in.
    static func replacingBody(of message: Data, with entity: Data) -> Data {
        // Lenient: headers are ASCII by specification, and a stray byte must
        // not hide a header.
        // swiftlint:disable:next optional_data_string_conversion
        let block = String(decoding: headerBlock(in: message), as: UTF8.self)
        var fields: [String] = []
        for line in block.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            if line.first == " " || line.first == "\t", !fields.isEmpty {
                fields[fields.count - 1] += "\r\n" + line
            } else if !line.isEmpty {
                fields.append(String(line))
            }
        }
        let envelope = fields.filter { !$0.lowercased().hasPrefix("content-") }
        var out = Data(envelope.map { $0 + "\r\n" }.joined().utf8)
        out.append(normalizedToCRLF(entity))
        return out
    }

    // MARK: - Content-Type

    /// The message's own Content-Type value, unfolded; nil when there is none
    /// or more than one. Which of two Content-Type headers Mail would go by is
    /// not ours to guess.
    static func contentType(of data: Data) -> String? {
        let values = headerValues("content-type", in: data)
        return values.count == 1 ? values[0] : nil
    }

    /// Every value of header `name` in the header block, in order, with folded
    /// continuation lines joined (RFC 5322 §2.2.3). Reading only the first
    /// line made a folded `From:` look empty, which skipped the check that
    /// the signer carries the sender's address.
    static func headerValues(_ name: String, in data: Data) -> [String] {
        // Lenient: headers are ASCII by specification, and a stray byte must
        // not hide a header.
        // swiftlint:disable:next optional_data_string_conversion
        let block = String(decoding: headerBlock(in: data), as: UTF8.self)
        let prefix = name.lowercased() + ":"
        var values: [String] = []
        var current: String?
        // "\r\n" is a single Character, so it is a separator of its own.
        for line in block.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" }) {
            if line.first == " " || line.first == "\t" {
                if let value = current {
                    let continuation = line.trimmingCharacters(in: .whitespaces)
                    current = value.isEmpty ? continuation : value + " " + continuation
                }
                continue
            }
            if let value = current { values.append(value) }
            current = nil
            if line.lowercased().hasPrefix(prefix) {
                current = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
            }
        }
        if let value = current { values.append(value) }
        return values
    }

    /// `type/subtype` of a Content-Type value, lowercased.
    static func mediaType(of contentType: String) -> String {
        (contentType.split(separator: ";").first ?? "")
            .trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// A parameter of a Content-Type value, quoted or not. Boundaries and
    /// protocol names cannot contain ";" (RFC 2046 §5.1.1).
    static func parameter(_ name: String, in contentType: String) -> String? {
        for piece in contentType.split(separator: ";").dropFirst() {
            let pair = piece.split(separator: "=", maxSplits: 1)
            guard pair.count == 2,
                  pair[0].trimmingCharacters(in: .whitespaces).lowercased() == name else { continue }
            var value = pair[1].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = String(value.dropFirst().dropLast())
            }
            return value
        }
        return nil
    }

    // MARK: - Multipart/signed parser

    /// Canonical CRLF form, byte-wise.
    private static func normalizedToCRLF(_ data: Data) -> Data {
        let cr: UInt8 = 0x0D, lf: UInt8 = 0x0A
        var out = Data()
        out.reserveCapacity(data.count + data.count / 8)
        var index = data.startIndex
        while index < data.endIndex {
            let byte = data[index]
            if byte == cr {
                let next = data.index(after: index)
                out.append(cr); out.append(lf)
                index = (next < data.endIndex && data[next] == lf) ? data.index(after: next) : next
            } else if byte == lf {
                out.append(cr); out.append(lf)
                index = data.index(after: index)
            } else {
                out.append(byte)
                index = data.index(after: index)
            }
        }
        return out
    }

    /// Pull the signed content and the detached signature out of a
    /// multipart/signed message, cut on the boundary of its own Content-Type,
    /// so gpg verifies exactly the part Mail displays.
    ///
    /// Works entirely in bytes. The signed content is fed to `gpg --verify`, so
    /// it has to be exactly the bytes the sender signed — and this ran through
    /// a Swift String, which meant a message whose body is not UTF-8 either
    /// bailed out with no verification at all, or, had the decode been made
    /// lenient, would have had its bytes replaced and reported a valid
    /// signature as invalid. A false alarm on a good signature is worse than
    /// no verdict.
    static func signedParts(of data: Data) -> (signed: Data, signature: Data)? {
        guard let contentType = contentType(of: data),
              mediaType(of: contentType) == "multipart/signed",
              parameter("protocol", in: contentType)?.lowercased() == "application/pgp-signature",
              let boundary = parameter("boundary", in: contentType), !boundary.isEmpty,
              let headersEnd = endOfHeaders(in: data) else { return nil }

        // RFC 1847: exactly two parts, the signed entity and the signature.
        let parts = bodyParts(of: data[headersEnd.upperBound...], boundary: boundary)
        guard parts.count == 2 else { return nil }

        // The signature part: skip its headers, keep the armoured block.
        let sigPart = parts[1]
        guard let sepRange = endOfHeaders(in: sigPart) else { return nil }
        // The armoured signature is ASCII; a stray byte makes gpg report the
        // signature as bad rather than skipping verification.
        // swiftlint:disable:next optional_data_string_conversion
        let sigBody = String(decoding: sigPart[sepRange.upperBound...], as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !sigBody.isEmpty else { return nil }

        // The signed data is the complete first part, headers included. We
        // sign the CRLF canonical form (RFC 3156 §5); stored messages often
        // use LF, so normalise before verifying.
        return (normalizedToCRLF(parts[0]), Data(sigBody.utf8))
    }

    /// The parts of a multipart body (RFC 2046 §5.1.1). A delimiter is
    /// "--boundary" at the start of a line followed by nothing but white space,
    /// and the line break before it belongs to the delimiter, not the part;
    /// "--boundary--" closes. The boundary string anywhere else is text.
    static func bodyParts(of body: Data, boundary: String) -> [Data] {
        let lf: UInt8 = 0x0A, cr: UInt8 = 0x0D, dash: UInt8 = 0x2D
        let delimiter = Data(("--" + boundary).utf8)
        var parts: [Data] = []
        var partStart: Data.Index?   // nil in the preamble
        var lineStart = body.startIndex
        while lineStart < body.endIndex {
            let newline = body[lineStart...].firstIndex(of: lf)
            var line = body[lineStart..<(newline ?? body.endIndex)]
            if line.last == cr { line = line.dropLast() }
            let next = newline.map { body.index(after: $0) } ?? body.endIndex
            if line.starts(with: delimiter) {
                var rest = line.dropFirst(delimiter.count)
                let closing = rest.starts(with: [dash, dash])
                if closing { rest = rest.dropFirst(2) }
                if rest.allSatisfy({ $0 == 0x20 || $0 == 0x09 }) {
                    if let start = partStart {
                        var end = lineStart
                        if end > start, body[body.index(before: end)] == lf { end = body.index(before: end) }
                        if end > start, body[body.index(before: end)] == cr { end = body.index(before: end) }
                        parts.append(Data(body[start..<end]))
                    }
                    if closing { return parts }
                    partStart = next
                }
            }
            lineStart = next
        }
        // No closing delimiter: the last part runs to the end.
        if let start = partStart, start < body.endIndex { parts.append(Data(body[start...])) }
        return parts
    }
}
