// LocalKeyserver.swift
// MailGPGTests – test infrastructure

import Foundation

/// An HKP keyserver on 127.0.0.1 that counts the requests it gets and answers
/// each with `armoredKey`, or with a 404 when it has none. Tests point
/// `GPGServiceImpl(keyservers:)` at `url` to see whether a call goes online.
/// It serves until the test process ends.
nonisolated final class LocalKeyserver: @unchecked Sendable {

    /// `hkp://localhost:<port>`. dirmngr finds no keyserver at `hkp://127.0.0.1`.
    let url: String
    private let socket: Int32
    private let armoredKey: String?
    private let lock = NSLock()
    private var _requests = 0

    /// The requests answered so far.
    var requests: Int { lock.withLock { _requests } }

    init(armoredKey: String? = nil) throws {
        self.armoredKey = armoredKey
        let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_port = 0
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(socket, $0, len) == 0 && listen(socket, 8) == 0
                    && getsockname(socket, $0, &len) == 0
            }
        }
        guard bound else {
            close(socket)
            throw NSError(domain: "LocalKeyserver", code: Int(errno))
        }
        self.socket = socket
        url = "hkp://localhost:\(UInt16(bigEndian: addr.sin_port))"
        Thread.detachNewThread { [self] in serve() }
    }

    private func serve() {
        while true {
            let client = accept(socket, nil, nil)
            guard client >= 0 else { return }
            var request = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while request.range(of: Data("\r\n\r\n".utf8)) == nil {
                let count = read(client, &buffer, buffer.count)
                guard count > 0 else { break }
                request.append(contentsOf: buffer[0..<count])
            }
            lock.withLock { _requests += 1 }
            let body = Data((armoredKey ?? "").utf8)
            let head = "HTTP/1.1 \(armoredKey == nil ? "404 Not Found" : "200 OK")\r\n"
                + "Content-Type: application/pgp-keys\r\n"
                + "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n"
            let response = Data(head.utf8) + body
            _ = response.withUnsafeBytes { write(client, $0.baseAddress, response.count) }
            close(client)
        }
    }
}
