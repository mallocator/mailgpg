// GPGServiceConnectionTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

/// The one host call these tests make, under the selector `GPGXPCProtocol` uses.
@objc protocol PingHostProtocol {
    func ping(reply: @escaping (_ gpgVersion: String?, Error?) -> Void)
}

/// Stands in for the host app over a real, in-process XPC connection. On the
/// first connection a ping drops the connection instead of replying, as a host
/// app that quits mid-call does, when `dies` is set.
private nonisolated final class PingHost: NSObject, NSXPCListenerDelegate, PingHostProtocol, @unchecked Sendable {
    let listener = NSXPCListener.anonymous()
    private let lock = NSLock()
    private var dying: NSXPCConnection?
    private var dies: Bool

    init(dies: Bool = false) {
        self.dies = dies
        super.init()
        listener.delegate = self
        listener.resume()
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: PingHostProtocol.self)
        connection.exportedObject = self
        lock.withLock {
            if dies { dying = connection; dies = false }
        }
        connection.resume()
        return true
    }

    func ping(reply: @escaping (String?, Error?) -> Void) {
        let current = NSXPCConnection.current()
        if let current, lock.withLock({ current === dying }) {
            current.invalidate()
        } else {
            reply("ok", nil)
        }
    }
}

/// Every connection the client made, and every availability it reported.
private nonisolated final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var _connections: [NSXPCConnection] = []
    private var _reported: [Bool] = []

    var connections: [NSXPCConnection] { lock.withLock { _connections } }
    var reported: [Bool] { lock.withLock { _reported } }

    func add(_ connection: NSXPCConnection) { lock.withLock { _connections.append(connection) } }
    func report(_ available: Bool) { lock.withLock { _reported.append(available) } }
}

final class GPGServiceConnectionTests: XCTestCase {

    private var host: PingHost!
    private var recorder: Recorder!
    private var client: GPGServiceConnection!

    private func start(hostDies: Bool = false) {
        let host = PingHost(dies: hostDies)
        let recorder = Recorder()
        client = GPGServiceConnection(retryDelay: .milliseconds(50)) {
            let connection = NSXPCConnection(listenerEndpoint: host.listener.endpoint)
            recorder.add(connection)
            return connection
        }
        client.onAvailabilityChanged = { recorder.report($0) }
        self.host = host
        self.recorder = recorder
    }

    override func tearDown() {
        recorder?.connections.forEach { $0.invalidate() }
        host?.listener.invalidate()
        super.tearDown()
    }

    private func ping() async throws -> String {
        let client = client!
        return try await Task.detached {
            try await withXPCReply(proxy: client.proxy(onError:)) { proxy, relay in
                proxy.ping { version, error in
                    if let error { relay.resume(throwing: error); return }
                    relay.resume(returning: version ?? "")
                }
            }
        }.value
    }

    /// The host app restarting while Mail is idle interrupts the connection.
    /// The connection stays usable (launchd starts the host app again on the
    /// next message), so it must not report the host app as unavailable: the
    /// extension would then never ping again and every compose window would
    /// offer no signing or encryption.
    func testInterruptionKeepsTheHostAppAvailable() async throws {
        start()
        _ = try await ping()
        let connection = try XCTUnwrap(recorder.connections.first)

        connection.interruptionHandler?()

        XCTAssertEqual(recorder.reported.last, true)
        let answer = try await ping()
        XCTAssertEqual(answer, "ok")
        XCTAssertEqual(recorder.connections.count, 1)
    }

    /// Calls in flight when the host app goes away all fail with an
    /// interruption. The connection survives that, so they must neither
    /// replace it (each failure used to schedule a reconnect of its own, every
    /// one a new connection and a new host-side service) nor report the host
    /// app unavailable.
    func testFailedCallsKeepTheConnection() async throws {
        start(hostDies: true)
        let failures = await withTaskGroup(of: Int?.self) { group in
            for _ in 0..<3 {
                group.addTask {
                    do { _ = try await self.ping(); return nil } catch { return (error as NSError).code }
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        XCTAssertEqual(failures, Array(repeating: NSXPCConnectionInterrupted, count: 3))

        // Several retry delays: any reconnect that was scheduled has run.
        try await Task.sleep(for: .milliseconds(500))
        let answer = try await ping()
        XCTAssertEqual(answer, "ok")
        XCTAssertEqual(recorder.connections.count, 1)
        XCTAssertFalse(recorder.reported.contains(false))
    }

    /// An invalidated connection is replaced once, after the retry delay.
    func testInvalidationReconnectsOnce() async throws {
        start()
        _ = try await ping()
        let connection = try XCTUnwrap(recorder.connections.first)

        connection.invalidate()
        try await Task.sleep(for: .milliseconds(500))

        XCTAssertEqual(recorder.connections.count, 2)
        XCTAssertEqual(recorder.reported, [true, false, true])
        let answer = try await ping()
        XCTAssertEqual(answer, "ok")
        XCTAssertEqual(recorder.connections.count, 2)
    }
}
