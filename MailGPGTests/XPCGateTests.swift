// XPCGateTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

/// Answers pings on an in-process listener, behind the host app's gate.
private nonisolated final class GatedHost: NSObject, NSXPCListenerDelegate, PingHostProtocol, @unchecked Sendable {
    let listener = NSXPCListener.anonymous()
    private let lock = NSLock()
    private var _pings = 0
    var pings: Int { lock.withLock { _pings } }

    override init() {
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        GPGServiceListener.requireOurExtension(connection)
        connection.exportedInterface = NSXPCInterface(with: PingHostProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func ping(reply: @escaping (String?, Error?) -> Void) {
        lock.withLock { _pings += 1 }
        reply("ok", nil)
    }
}

final class XPCGateTests: XCTestCase {

    /// The test runner is not our signed extension, so its calls never arrive.
    func testGate_refusesAPeerThatIsNotOurExtension() throws {
        let host = GatedHost()
        let connection = NSXPCConnection(listenerEndpoint: host.listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: PingHostProtocol.self)
        connection.resume()
        defer { connection.invalidate() }

        let failed = expectation(description: "call fails")
        let proxy = connection.remoteObjectProxyWithErrorHandler { _ in failed.fulfill() }
        try XCTUnwrap(proxy as? PingHostProtocol).ping { _, _ in XCTFail("the call got through") }
        wait(for: [failed], timeout: 5)
        XCTAssertEqual(host.pings, 0)
    }
}
