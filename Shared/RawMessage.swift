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

    /// Classify a message from its header block first, and scan the body for
    /// inline armour only when the headers do not decide.
    ///
    /// The whole header block is scanned rather than a fixed prefix: routing
    /// headers added by Gmail, Exchange, etc. (DKIM, ARC, Received, ...) can push
    /// Content-Type well past 4 KB. When it says RFC 3156 either way, the body
    /// is not looked at: a multipart/signed message quoting an armoured
    /// encrypted block was otherwise taken down the decrypt path, labelled
    /// encrypted, and its real signature never verified. The body scans are
    /// byte searches, so ordinary large messages never become a Swift String.
    static func pgpContent(of data: Data) -> PGPContent {
        // Lenient: headers are ASCII by specification, and a stray byte must
        // not hide the Content-Type.
        // swiftlint:disable:next optional_data_string_conversion
        let headers = String(decoding: headerBlock(in: data), as: UTF8.self).lowercased()
        if headers.contains("multipart/encrypted") && headers.contains("application/pgp-encrypted") {
            return PGPContent(isEncrypted: true, isSigned: false)
        }
        if headers.contains("multipart/signed") && headers.contains("application/pgp-signature") {
            return PGPContent(isEncrypted: false, isSigned: true)
        }
        // Inline PGP (e.g. Mailvelope): the armour is in the body.
        return PGPContent(isEncrypted: data.range(of: inlineMessageMarker) != nil,
                          isSigned: data.range(of: inlineSignedMarker) != nil)
    }
}
