// GPGServiceListener.swift
// MailGPG (host app only)

import Foundation
import os

/// The Mach service name both sides must agree on.
/// Think of it like a port number — the extension dials this name,
/// the host app listens on it.
let GPGServiceName = "net.pyxzl.mailgpg.gpgservice"

/// Sets up and runs the XPC listener on the host-app side.
///
/// `NSXPCListener` is the server half of XPC. When the extension calls
/// `NSXPCConnection(machServiceName:)`, the OS routes that connection
/// request here. We then decide whether to accept it.
final class GPGServiceListener: NSObject, NSXPCListenerDelegate {

    private let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: GPGServiceName)
        super.init()
        listener.delegate = self
    }

    /// Call once at app launch. The listener runs until the app quits.
    func start() {
        listener.resume()
        log.info("listener started on \(GPGServiceName, privacy: .public)")
    }

    // MARK: - NSXPCListenerDelegate

    /// Called by XPC for every incoming connection attempt.
    /// Return `true` to accept, `false` to reject.
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {

        // Security check: only our own extension may talk to us. Without it,
        // any app on the machine could ask us to run GPG.
        Self.requireOurExtension(connection)

        // Tell XPC what protocol the remote side (extension) can call on us.
        connection.exportedInterface = NSXPCInterface(with: GPGXPCProtocol.self)

        // The object that actually handles the calls — created fresh per connection.
        connection.exportedObject = GPGServiceImpl()

        // Must call resume() or the connection stays suspended and nothing works.
        connection.resume()

        log.info("accepted XPC connection, open to the Mail extension only")
        return true
    }

    // MARK: - Security validation

    /// A bundle identifier on its own is a self-declared string: ANY binary,
    /// ad-hoc signed by anyone, can claim it and satisfy `identifier "..."`.
    /// Without the anchor and team-ID clauses below, any process running as
    /// the user could open this Mach service and use it as a signing and
    /// decryption oracle — silently, because gpg-agent caches the passphrase.
    ///
    ///   anchor apple generic  → the cert chain really is an Apple-issued one
    ///   subject.OU            → the leaf cert belongs to our Developer team
    ///
    /// Both "Apple Development" and "Developer ID Application" certificates
    /// carry the team ID in the leaf OU, so this holds for local debug builds
    /// and notarised release builds alike.
    static let extensionRequirement = """
        identifier "net.pyxzl.MailGPG.MailGPGExtension" \
        and anchor apple generic \
        and certificate leaf[subject.OU] = "3HKD37M482"
        """

    /// Let `connection` deliver messages only from a peer that satisfies
    /// `extensionRequirement`. XPC checks the peer's audit token on every message, so
    /// unlike a lookup by PID, a reused PID or an exec after connecting does
    /// not pass. A peer that fails gets its connection invalidated before any
    /// call reaches us; on a healthy machine that is a broken install or
    /// something local trying to use our keys.
    static func requireOurExtension(_ connection: NSXPCConnection) {
        connection.setCodeSigningRequirement(extensionRequirement)
    }
}
