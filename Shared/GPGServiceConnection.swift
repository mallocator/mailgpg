// GPGServiceConnection.swift
// Shared — add to both MailGPG and MailGPGExtension targets
//
// Only the extension uses it; it lives in Shared so the tests can run it
// against a real XPC connection.

import Foundation
import os

private let xpcLog = Logger(subsystem: "net.pyxzl.mailgpg", category: "xpc")

/// Manages the lifecycle of the XPC connection from the extension to the host app.
///
/// ## Ownership
/// `GPGService` (the actor) holds the single instance of this class.
/// Don't create it anywhere else.
///
/// ## Connection states
///
///   nil connection → connect() → connected
///                                    │
///                         interruptionHandler (host app crashed/restarted)
///                                    │
///                              XPC auto-reconnects on next message send
///                                    │
///                         invalidationHandler (host app quit cleanly)
///                                    │
///                              connection = nil → scheduleReconnect()
///                                    │
///                         after delay → connect() again (up to maxRetries)
///
/// There is at most one connection: `connect()` does nothing while one exists,
/// and only the current connection's invalidation drops it. A failed call
/// leaves the connection alone; if the failure invalidated it, its
/// invalidation handler runs too.
///
nonisolated final class GPGServiceConnection: @unchecked Sendable {

    // MARK: - Configuration

    private let maxRetries = 3
    private let retryDelay: Duration
    private let makeConnection: () -> NSXPCConnection

    // MARK: - State

    private var connection: NSXPCConnection?
    private var retryCount = 0

    /// Guards the mutable fields.
    ///
    /// `proxy(onError:)` is called from the GPGService actor, but XPC delivers its
    /// interruption and invalidation handlers on its own queues, and the
    /// reconnect runs in a detached Task — so these are written from several
    /// threads with no relationship to each other. Concurrent access to a
    /// Swift var is undefined behaviour, and here it would corrupt an object
    /// reference.
    private let lock = NSLock()

    // Called by GPGService when availability changes, so it can update
    // any published state the UI observes. `true`: a usable connection exists
    // (whether the host app answers on it is not known yet); `false`: none.
    var onAvailabilityChanged: ((Bool) -> Void)?

    /// `makeConnection` returns a new, unconfigured connection to the host app;
    /// tests pass one to an in-process listener.
    init(retryDelay: Duration = .seconds(2),
         makeConnection: @escaping () -> NSXPCConnection = {
             NSXPCConnection(machServiceName: "net.pyxzl.mailgpg.gpgservice")
         }) {
        self.retryDelay = retryDelay
        self.makeConnection = makeConnection
    }

    // MARK: - Public API

    /// Returns a proxy object the caller can cast to `GPGXPCProtocol` and call methods on.
    /// Throws `GPGXPCError.hostAppNotRunning` if no connection is available.
    ///
    /// `onError` runs when a call made on this proxy fails at the XPC layer.
    /// NSXPC then never calls the method's reply block, so `onError` is the
    /// caller's only chance to fail whatever awaits that reply — see
    /// `withXPCReply`.
    func proxy(onError: @escaping @Sendable (Error) -> Void) throws -> GPGXPCProtocol {
        connect()

        lock.lock()
        let current = connection
        lock.unlock()

        guard let conn = current else {
            throw GPGXPCError.make(.hostAppNotRunning,
                message: GPGXPCError.hostAppNotRunningMessage)
        }

        // `remoteObjectProxyWithErrorHandler` returns a proxy object.
        // Any XPC error that occurs mid-call is delivered to the error handler,
        // which hands it back to the caller. The connection's own handlers
        // track availability: one call failing says nothing the interruption
        // or invalidation handler doesn't, and every call in flight fails.
        let proxy = conn.remoteObjectProxyWithErrorHandler { error in
            let nsError = error as NSError
            xpcLog.error("remote error domain=\(nsError.domain, privacy: .public) code=\(nsError.code)")
            onError(error)
        }

        // We configured the interface with GPGXPCProtocol, so XPC hands back a
        // proxy that conforms to it; anything else is an unusable connection.
        guard let typed = proxy as? GPGXPCProtocol else {
            throw GPGXPCError.make(.hostAppNotRunning,
                message: "XPC proxy does not conform to GPGXPCProtocol.")
        }
        return typed
    }

    // MARK: - Connection management

    private func connect() {
        lock.lock()
        guard connection == nil else { lock.unlock(); return }
        let conn = makeConnection()

        // Tell XPC what protocol the host app (remote side) implements.
        let interface = NSXPCInterface(with: GPGXPCProtocol.self)

        // XPC needs to know about [String] parameters explicitly — without this,
        // any method that sends an array of strings across the boundary will be
        // rejected at runtime. We register each affected method here.
        configureArrayTypes(on: interface)
        conn.remoteObjectInterface = interface

        // Interruption = host app crashed or restarted. The connection stays
        // usable: launchd starts the host app again on the next message. So
        // availability goes back to unknown rather than to unavailable, which
        // nothing would ever reset, and the next compose window pings.
        conn.interruptionHandler = { [weak self] in
            xpcLog.error("connection interrupted — host app may have crashed")
            self?.setAvailable(true)
        }

        // Invalidation = host app quit cleanly or was killed. The connection
        // object is now dead and must be replaced. We schedule a reconnect.
        conn.invalidationHandler = { [weak self, weak conn] in
            xpcLog.info("connection invalidated — host app quit")
            if let conn { self?.handleInvalidation(of: conn) }
        }

        connection = conn
        // A successful connection ends the incident. Without this the retry
        // budget was spent once for the lifetime of the extension rather than
        // once per outage, so the fourth time the host app ever restarted, the
        // extension stopped reconnecting on its own.
        retryCount = 0
        lock.unlock()
        // Resumed only once it is `connection`, so its handlers find it there.
        conn.resume()
        setAvailable(true)
        xpcLog.info("connected to the host app")
    }

    private func handleInvalidation(of conn: NSXPCConnection) {
        lock.lock()
        guard connection === conn else { lock.unlock(); return }
        connection = nil
        let attempts = retryCount
        if attempts < maxRetries { retryCount += 1 } else { retryCount = 0 }
        lock.unlock()
        setAvailable(false)

        guard attempts < maxRetries else {
            xpcLog.error("max reconnect attempts reached — waiting for the next request")
            return
        }

        xpcLog.info("scheduling reconnect attempt \(attempts + 1)/\(self.maxRetries)")

        // `Task` here runs in the Swift concurrency pool. We sleep, then try again.
        Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(for: retryDelay)
            self.connect()
        }
    }

    private func setAvailable(_ value: Bool) {
        lock.lock()
        let notify = onAvailabilityChanged
        lock.unlock()
        // Called outside the lock: the callback runs GPGService code, and
        // holding our lock across it invites a deadlock the day that code
        // calls back into this class.
        notify?(value)
    }

    // MARK: - XPC array type registration

    /// XPC is strict about collection types — you must declare that a parameter
    /// is an `NSArray` containing `NSString` elements, otherwise XPC refuses to
    /// send it across the process boundary and crashes at runtime.
    private func configureArrayTypes(on interface: NSXPCInterface) {
        // Metatypes (NSArray.self) are not directly Hashable in Swift.
        // Bridging via AnyObject gives us the Obj-C class object, which
        // IS an NSObject and therefore castable to AnyHashable.
        let stringArray = classSet(NSArray.self, NSString.self)

        // Both encrypt methods now carry two string arrays — the visible
        // recipients and the hidden (BCC) ones. Every array argument needs its
        // own declaration or XPC refuses to send it.

        // encrypt(data:recipientFingerprints:hiddenRecipientFingerprints:reply:)
        let encryptSelector = #selector(GPGXPCProtocol.encrypt(data:recipientFingerprints:hiddenRecipientFingerprints:reply:))
        for index in 1...2 {
            interface.setClasses(stringArray, for: encryptSelector,
                                 argumentIndex: index, ofReply: false)
        }

        // signAndEncrypt(data:signerKeyID:recipientFingerprints:hiddenRecipientFingerprints:reply:)
        let signEncryptSelector = #selector(GPGXPCProtocol.signAndEncrypt(data:signerKeyID:recipientFingerprints:hiddenRecipientFingerprints:reply:))
        for index in 2...3 {
            interface.setClasses(stringArray, for: signEncryptSelector,
                                 argumentIndex: index, ofReply: false)
        }
    }

    /// Builds a `Set<AnyHashable>` from Obj-C class objects.
    /// The bridge `as AnyObject` converts the Swift metatype to an Obj-C class
    /// object. Taking `NSObject.Type` means every class object is an NSObject
    /// instance, which is Hashable, so the conditional cast never drops one.
    private func classSet(_ classes: NSObject.Type...) -> Set<AnyHashable> {
        Set(classes.compactMap { $0 as AnyObject as? AnyHashable })
    }
}
