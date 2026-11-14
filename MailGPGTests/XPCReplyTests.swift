// XPCReplyTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

@objc protocol StubHostProtocol {
    func echo(_ text: String, reply: @escaping (String?, Error?) -> Void)
    func dieMidCall(reply: @escaping (String?, Error?) -> Void)
}

/// Stands in for the host app over a real, in-process XPC connection.
private nonisolated final class StubHost: NSObject, NSXPCListenerDelegate, StubHostProtocol {
    let listener = NSXPCListener.anonymous()

    override init() {
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: StubHostProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func echo(_ text: String, reply: @escaping (String?, Error?) -> Void) {
        reply(text, nil)
    }

    /// The host app going away with a call in flight: the connection drops and
    /// the reply block is never called.
    func dieMidCall(reply: @escaping (String?, Error?) -> Void) {
        NSXPCConnection.current()?.invalidate()
    }
}

final class XPCReplyTests: XCTestCase {

    private var host: StubHost!
    private var connection: NSXPCConnection!

    override func setUp() {
        super.setUp()
        host = StubHost()
        connection = NSXPCConnection(listenerEndpoint: host.listener.endpoint)
        connection.remoteObjectInterface = NSXPCInterface(with: StubHostProtocol.self)
        connection.resume()
    }

    override func tearDown() {
        connection.invalidate()
        host.listener.invalidate()
        super.tearDown()
    }

    private func call(_ send: @escaping @Sendable (StubHostProtocol, OneShotRelay<String>) -> Void)
        -> (XCTestExpectation, () -> Result<String, Error>?) {
        let done = expectation(description: "call finished")
        let lock = NSLock()
        nonisolated(unsafe) var result: Result<String, Error>?
        let connection = connection!
        Task.detached {
            let outcome: Result<String, Error>
            do {
                outcome = .success(try await withXPCReply(proxy: { onError in
                    connection.remoteObjectProxyWithErrorHandler(onError) as! StubHostProtocol
                }, send))
            } catch {
                outcome = .failure(error)
            }
            lock.withLock { result = outcome }
            done.fulfill()
        }
        return (done, { lock.withLock { result } })
    }

    func testReplyResumesCall() async {
        let (done, result) = call { proxy, relay in
            proxy.echo("hello") { text, error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: text ?? "")
            }
        }
        await fulfillment(of: [done], timeout: 5)
        XCTAssertEqual(try result()?.get(), "hello")
    }

    /// NSXPC calls the proxy's error handler instead of the reply block when
    /// the connection drops; the await must still finish, with that error.
    func testHostDyingMidCallFailsTheCall() async {
        let (done, result) = call { proxy, relay in
            proxy.dieMidCall { text, error in
                if let error { relay.resume(throwing: error); return }
                relay.resume(returning: text ?? "")
            }
        }
        await fulfillment(of: [done], timeout: 5)
        guard case .failure(let error as NSError)? = result() else {
            return XCTFail("expected the call to fail, got \(String(describing: result()))")
        }
        XCTAssertEqual(error.domain, NSCocoaErrorDomain)
    }

    func testProxyFailureFailsTheCall() async {
        let refused = NSError(domain: "test", code: 1)
        do {
            let _: String = try await withXPCReply(proxy: { _ -> StubHostProtocol in throw refused }) { _, _ in
                XCTFail("sent despite having no proxy")
            }
            XCTFail("expected the call to fail")
        } catch {
            XCTAssertEqual(error as NSError, refused)
        }
    }
}
