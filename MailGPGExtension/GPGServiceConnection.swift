// GPGServiceConnection.swift
// MailGPGExtension (extension only)

import Foundation
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "xpc")

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
final class GPGServiceConnection {

    // MARK: - Configuration

    private let serviceName = "net.pyxzl.mailgpg.gpgservice"
    private let maxRetries  = 3
    private let retryDelay  = Duration.seconds(2)

    // MARK: - State

    private var connection: NSXPCConnection?
    private var retryCount = 0

    /// Guards the three mutable fields below.
    ///
    /// `proxy()` is called from the GPGService actor, but XPC delivers its
    /// interruption and invalidation handlers on its own queues, and the
    /// reconnect runs in a detached Task — so these are written from several
    /// threads with no relationship to each other. Concurrent access to a
    /// Swift var is undefined behaviour, and here it would corrupt an object
    /// reference.
    private let lock = NSLock()

    /// `true` while a valid connection exists. Observed by `GPGService`
    /// to decide whether to surface a "host app not running" error.
    private(set) var isAvailable = false

    // Called by GPGService when availability changes, so it can update
    // any published state the UI observes.
    var onAvailabilityChanged: ((Bool) -> Void)?

    // MARK: - Public API

    /// Returns a proxy object the caller can cast to `GPGXPCProtocol` and call methods on.
    /// Throws `GPGXPCError.hostAppNotRunning` if no connection is available.
    func proxy() throws -> GPGXPCProtocol {
        lock.lock()
        let existing = connection
        lock.unlock()
        if existing == nil { connect() }

        lock.lock()
        let current = connection
        lock.unlock()

        guard let conn = current else {
            throw GPGXPCError.make(.hostAppNotRunning,
                message: "MailGPG host app is not running. Please open it to enable GPG operations.")
        }

        // `remoteObjectProxyWithErrorHandler` returns a proxy object.
        // Any XPC error that occurs mid-call is delivered to the error handler,
        // which we route into our availability tracking.
        let proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
            let nsError = error as NSError
            log.error("remote error domain=\(nsError.domain, privacy: .public) code=\(nsError.code)")
            self?.handleInvalidation()
        }

        // Force-cast is safe here: we configured the interface with GPGXPCProtocol,
        // so XPC guarantees the proxy conforms to it.
        return proxy as! GPGXPCProtocol
    }

    // MARK: - Connection management

    private func connect() {
        let conn = NSXPCConnection(machServiceName: serviceName)

        // Tell XPC what protocol the host app (remote side) implements.
        conn.remoteObjectInterface = NSXPCInterface(with: GPGXPCProtocol.self)

        // XPC needs to know about [String] parameters explicitly — without this,
        // any method that sends an array of strings across the boundary will be
        // rejected at runtime. We register each affected method here.
        configureArrayTypes(on: conn.remoteObjectInterface!)

        // Interruption = host app crashed but will restart. XPC buffers outgoing
        // calls and replays them once the host app reconnects. We just log it.
        conn.interruptionHandler = { [weak self] in
            log.error("connection interrupted — host app may have crashed")
            self?.setAvailable(false)
        }

        // Invalidation = host app quit cleanly or was killed. The connection
        // object is now dead and must be replaced. We schedule a reconnect.
        conn.invalidationHandler = { [weak self] in
            log.info("connection invalidated — host app quit")
            self?.handleInvalidation()
        }

        conn.resume()
        lock.lock()
        connection = conn
        // A successful connection ends the incident. Without this the retry
        // budget was spent once for the lifetime of the extension rather than
        // once per outage, so the fourth time the host app ever restarted, the
        // extension stopped reconnecting on its own.
        retryCount = 0
        lock.unlock()
        setAvailable(true)
        log.info("connected to \(self.serviceName, privacy: .public)")
    }

    private func handleInvalidation() {
        lock.lock()
        connection = nil
        let attempts = retryCount
        if attempts < maxRetries { retryCount += 1 } else { retryCount = 0 }
        lock.unlock()
        setAvailable(false)

        guard attempts < maxRetries else {
            log.error("max reconnect attempts reached — waiting for the next request")
            return
        }

        log.info("scheduling reconnect attempt \(attempts + 1)/\(self.maxRetries)")

        // `Task` here runs in the Swift concurrency pool. We sleep, then try again.
        Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(for: retryDelay)
            self.connect()
        }
    }

    private func setAvailable(_ value: Bool) {
        lock.lock()
        isAvailable = value
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
    /// object; the force-cast to `AnyHashable` succeeds because Obj-C class
    /// objects are NSObject instances, which are Hashable.
    private func classSet(_ classes: AnyClass...) -> Set<AnyHashable> {
        Set(classes.map { $0 as AnyObject as! AnyHashable })
    }
}
